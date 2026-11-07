"""Derives a presence-oracle TSV from a benign-corpus presence report (.md).

Usage: python -I derive_oracle.py <report.md> <out.tsv> <header-file>
       python -I derive_oracle.py --check <report.md> <existing-oracle.tsv>

Records (tab-separated), in this order:
  manifest-hash, denominator, assemblies, methods-analysed, total-findings  (parameter table)
  capability <Name> <packages> <total>       ("Capability density", sorted by name, ordinal)
  package <id> <version> <tfm> <assemblies> <methods> <findings>   ("Per package", status 'scanned' only, table order)
  package-capability <id> <Capability> <n>   ("Findings by capability, per package", non-zero, table order)
Cross-checks: per-package findings == sum of its capability row; per-capability totals and package counts == the
per-package table's; denominator == scanned count. Any mismatch aborts.
"""
import sys


def tables(md):
    """Yields (heading, rows) for each markdown table, rows as lists of cell strings (header row included)."""
    heading, rows = None, []
    for line in md.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(set(c) <= set("-: ") for c in cells):
                rows.append(cells)
        elif rows:
            yield heading, rows
            rows = []
    if rows:
        yield heading, rows


def num(s):
    return int(s.replace("*", ""))


def derive(md):
    ts = list(tables(md))
    params = {r[0]: r[1].strip("`") for h, rows in ts if h.startswith("Benign corpus") for r in rows[1:]}
    density = next(rows for h, rows in ts if h.startswith("Capability density"))
    per_pkg = next(rows for h, rows in ts if h == "Per package")
    by_cap = next(rows for h, rows in ts if h == "Findings by capability, per package")

    caps = sorted((r[0], num(r[1]), num(r[3])) for r in density[1:] if not r[0].startswith("**"))
    scanned = [r for r in per_pkg[1:] if r[3] == "scanned"]
    abbrev = by_cap[0][1:]
    full = {c[0][:4]: c[0] for c in caps}
    cap_rows = {r[0]: dict(zip((full[a] for a in abbrev), map(num, r[1:]))) for r in by_cap[1:]}

    out = [
        ("manifest-hash", params["Manifest hash (sha256 of normalized `id,version` list)"]),
        ("denominator", params["Packages contributing to density"]),
        ("assemblies", params["Assemblies scanned"]),
        ("methods-analysed", params["Methods analysed"]),
        ("total-findings", params["Total findings"]),
    ]
    out += [("capability", n, str(p), str(t)) for n, p, t in caps]
    out += [("package", r[0], r[1], r[2], r[4], r[5], r[7]) for r in scanned]
    for r in scanned:
        out += [("package-capability", r[0], c, str(v)) for c, v in sorted(cap_rows[r[0]].items()) if v]

    # Cross-checks: explicit, so `python -O` cannot strip them.
    check(int(params["Packages contributing to density"]) == len(scanned), "denominator != scanned packages")
    for r in scanned:
        check(sum(cap_rows[r[0]].values()) == num(r[7]), f"{r[0]}: findings != sum of capabilities")
    for n, p, t in caps:
        check(sum(cap_rows[r[0]][n] for r in scanned) == t, f"{n}: total mismatch")
        check(sum(1 for r in scanned if cap_rows[r[0]][n]) == p, f"{n}: package count mismatch")
    check(sum(num(r[7]) for r in scanned) == int(params["Total findings"]), "total findings mismatch")
    return ["\t".join(row) for row in out]


def check(ok, message):
    if not ok:
        raise ValueError(f"cross-check failed: {message}")


def body(path):
    return [l.rstrip("\r") for l in open(path, encoding="utf-8").read().split("\n") if l.strip() and not l.startswith("#")]


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        derived, existing = derive(open(sys.argv[2], encoding="utf-8").read()), body(sys.argv[3])
        same = derived == existing
        print(f"derived {len(derived)} records, existing {len(existing)}: {'IDENTICAL' if same else 'DIFFERENT'}")
        if not same:
            for i, (a, b) in enumerate(zip(derived, existing)):
                if a != b:
                    print(f"  first difference at record {i}: derived {a!r} existing {b!r}")
                    break
        sys.exit(0 if same else 1)
    report, out, header = sys.argv[1:4]
    lines = derive(open(report, encoding="utf-8").read())
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(open(header, encoding="utf-8").read())
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} records to {out}")
