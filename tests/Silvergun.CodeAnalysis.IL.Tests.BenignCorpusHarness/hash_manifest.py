"""Prints a markdown table of the SHA-256 of each manifest entry's cached .nupkg.

Usage: python -I hash_manifest.py <manifest> <package-cache-dir>
"""
import hashlib
import os
import sys

manifest, cache = sys.argv[1:3]
print("| Id | Version | SHA-256 of the .nupkg |\n|---|---|---|")
for line in open(manifest, encoding="utf-8"):
    t = line.strip()
    if not t or t.startswith("#"):
        continue
    pid, ver = (p.strip() for p in t.split(","))
    with open(os.path.join(cache, "packages", f"{pid}.{ver}.nupkg"), "rb") as f:
        print(f"| {pid} | {ver} | `{hashlib.sha256(f.read()).hexdigest()}` |")
