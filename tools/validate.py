"""
Check that every name really hashes to the value stored next to it.

    python tools/validate.py csv/*/*.csv     check files
    python tools/validate.py --add rows.csv  check pasted rows and file the good ones (`-` = stdin)

Exit code 1 if any row failed, 2 if --add found nothing new, else 0.
"""
import csv, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hashing

DATA = HERE.parent / "csv"
HEX16 = re.compile(r"^[0-9A-Fa-f]{16}$")
KIND = re.compile(r"^[a-z][a-z0-9_]{2,30}$")

# what a file's names are allowed to hash under; a row passes under any one of them
DIRS = {"treyarch": None, "vanguard": ["dvar_vanguard"]}   # treyarch is mixed, so anything goes
FILES = {
    "xanims.csv": ["asset"], "ximages.csv": ["asset"], "xmaterials.csv": ["asset"],
    "xsounds.csv": ["asset"], "soundbanks.csv": ["asset"], "animpkgs.csv": ["asset"],
    "gsc_scripts.csv": ["asset"], "lua_files.csv": ["asset"], "localize_keys.csv": ["asset"],
    "content_items.csv": ["asset"], "ui_widgets.csv": ["asset"], "assets_untyped.csv": ["asset"],
    "bones.csv": ["fnv"], "soundbanks_aliases.csv": ["fnv"],
    "dvars.csv": ["dvar"], "gsc_identifiers.csv": ["id"], "lua_functions.csv": ["fnv_lower"],
    "gsc_builtins.csv": ["id", "fnv", "fnv_lower"],
    "strings.csv": ["fnv", "fnv_lower", "fnv~63", "fnv_lower~63"],  # ~63 = top bit masked off
    "omnvars.csv": ["omnvar", "omnvar_salted"],
}

# where a pasted row goes, by the function that verified it; first match wins
FILE_FOR = {
    "asset": None,                       # asset names say what they are, see asset_file()
    "dvar": "iw/dvars.csv",
    "dvar_vanguard": "vanguard/dvars.csv",
    "id": "iw/gsc_identifiers.csv",
    "omnvar_salted": "iw/omnvars.csv",
    "omnvar": "iw/omnvars.csv",
    "fnv": None,                         # fnv names say what they are, see fnv_file()
    "fnv_lower": None,
    "fnv~63": None,
    "fnv_lower~63": None,
}


def reject(h, name, want=None):
    """Why this row is unacceptable, or None if it is fine."""
    if not HEX16.match(h):
        return "hash must be 16 hex digits"
    v = int(h, 16)
    if v >> 32 < 0x10000 and v & 0xFFFFFFFF < 0x10000:
        # an index from a table walk, not a hash; a name matching it was brute-forced
        return "not a hash (both 32-bit halves are tiny)"
    if not name:
        return "empty name"
    fams = hashing.verify(v, name)
    if not fams:
        return "does not hash to this value under any function"
    if want and not any(w in fams for w in want):
        return "does not verify under %s (it verifies under: %s)" % (" or ".join(want), ", ".join(fams))
    return None


def functions_for(path):
    if path.parent.name in DIRS:
        return DIRS[path.parent.name]
    if path.name not in FILES:
        raise SystemExit("unknown file %s; known: %s" % (path.name, ", ".join(sorted(FILES))))
    return FILES[path.name]


def fnv_file(name, fams=()):
    """Where an fnv row goes, by name shape; the counterpart of asset_file().

    bones.csv needs plain fnv and is all-lowercase. soundbanks_aliases.csv is left
    unrouted because its prefixes also occur on ordinary identifiers.
    """
    if ("fnv" in fams and name == name.lower()
            and (name.startswith(("j_", "tag_")) or name.endswith("_mesh"))):
        return "iw/bones.csv"
    return "iw/strings.csv"


def asset_file(name):
    n = name.lower()
    if n.endswith((".gsc", ".csc")):
        return "iw/gsc_scripts.csv"
    if n.endswith(".lua"):
        return "iw/lua_files.csv"
    if n.startswith("ui.generated."):
        return "iw/ui_widgets.csv"
    if ":" in n and KIND.match(n.split(":", 1)[0]):
        return "iw/content_items.csv"
    return "iw/assets_untyped.csv"


def rows(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                yield row[0], row[1]


def append(target, h, name):
    path = DATA / target
    empty = not path.exists() or path.stat().st_size == 0
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, lineterminator="\n")
        if empty:
            writer.writerow(["hash", "name"])
        writer.writerow([h, name])


def run_add(lines):
    # against every hash in the database, not just the target file, or a name already filed
    # under one function gets a second home under another
    seen = {h.upper() for p in DATA.glob("*/*.csv") for h, _ in rows(p)}
    filed, dup, bad = [], [], []
    for row in csv.reader(lines):
        if len(row) < 2 or row[0].lower() == "hash":
            continue
        h, name = row[0].strip().upper(), row[1]
        fams = hashing.verify(int(h, 16), name) if HEX16.match(h) else []
        fam = next((f for f in FILE_FOR if f in fams), None)
        if problem := reject(h, name):
            bad.append((h, name, problem))
        elif fam is None:
            bad.append((h, name, "verifies only under %s, which has no file here" % ", ".join(fams)))
        elif h in seen:
            dup.append((h, name))
        else:
            seen.add(h)
            target = (asset_file(name) if fam == "asset"
                      else fnv_file(name, fams) if fam.startswith("fnv")
                      else FILE_FOR[fam])
            append(target, h, name)
            filed.append((h, name, target))

    for tag, group in (("FILED", filed), ("DUPLICATE", dup), ("FAIL", bad)):
        for row in group:
            print(",".join((tag,) + row))
    print("%d filed, %d duplicates, %d failed" % (len(filed), len(dup), len(bad)))
    return 1 if bad else (0 if filed else 2)


def run_check(paths):
    ok = bad = 0
    for path in map(Path, paths):
        want = functions_for(path)
        for h, name in rows(path):
            if problem := reject(h, name, want):
                bad += 1
                print("FAIL,%s,%s,%s,%s" % (path, h, name.replace(",", "%2C"), problem))
            else:
                ok += 1
    print("%d ok, %d failed" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--add"]:
        src = sys.stdin if args[1:2] == ["-"] else open(args[1], encoding="utf-8", errors="replace", newline="")
        sys.exit(run_add(src))
    sys.exit(run_check(args))
