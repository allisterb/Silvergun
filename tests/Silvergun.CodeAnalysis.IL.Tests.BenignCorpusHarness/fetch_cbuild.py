"""C-build corpus selection and fetch (reachability R2b, S3).

Usage:
  python -I fetch_cbuild.py probe  <work-dir>
  python -I fetch_cbuild.py select <work-dir> <c100-manifest> <package-cache-dir> <out-manifest> <out-provenance>

Rules (pre-registered in docs/agent/tasks/reachability-r2b.md, S3):
  - candidates: NuGet V3 search for each query term, prerelease=false; union by id (case-insensitive)
  - ranked by totalDownloads desc (ties: id ordinal), latest stable version (the search result's version)
  - exclude C100 ids
  - keep a candidate iff its .nupkg has a .dll under analyzers/, build/, buildTransitive/, tasks/ or tools/
  - stop at 50 kept
Fetching: ~1 req/s, every response cached on disk, each resource fetched once. Stops on 429, 403 or a challenge.
No credentials, generic User-Agent, nothing personal sent.
Hardened after the 2026-11-06 fetch (S0-S3 review, Nit 4): a .nupkg response must start with the zip magic or the run
stops as a refusal (a challenge page served as HTTP 200), and ids and versions must match NuGet's character sets
before they name a cache file. Neither check would have changed that fetch: 0 refusals, every .nupkg a readable zip.
"""

import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

USER_AGENT = "Silvergun-corpus-fetch/1.0"
SERVICE_INDEX = "https://api.nuget.org/v3/index.json"
QUERIES = ["analyzers", "sourcegenerator", "generator", "msbuild"]
TAKE = 1000
KEEP = 50
BUILD_DIRS = {"analyzers", "build", "buildtransitive", "tasks", "tools"}

ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9.+-]{0,63}$")
ZIP_MAGIC = b"PK\x03\x04"

_last = [0.0]


class Refusal(Exception):
    pass


def fetch(url, cache_path, magic=None):
    """Returns the bytes of url, from cache_path if present; otherwise fetches once at <= 1 req/s. With magic, a
    response not starting with it is a refusal and is not cached."""
    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            return f.read()
    wait = 1.0 - (time.monotonic() - _last[0])
    if wait > 0:
        time.sleep(wait)
    _last[0] = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            status = r.status
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read()
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise Refusal(f"HTTP {e.code} for {url}")
        raise
    if headers.get("x-amzn-waf-action") or (status == 202 and not body):
        raise Refusal(f"challenge (HTTP {status}, waf={headers.get('x-amzn-waf-action')}) for {url}")
    if magic is not None and not body.startswith(magic):
        raise Refusal(f"not the expected content (HTTP {status}, {headers.get('content-type')}) for {url}")
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    tmp = cache_path + ".partial"
    with open(tmp, "wb") as f:
        f.write(body)
    os.replace(tmp, cache_path)
    print(f"  fetched {url} ({len(body)} bytes)", flush=True)
    return body


def robots(work, url):
    host = urllib.parse.urlparse(url).netloc
    try:
        return fetch(f"https://{host}/robots.txt", os.path.join(work, "robots", host + ".txt")).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"<HTTP {e.code}>"


def service(work):
    index = json.loads(fetch(SERVICE_INDEX, os.path.join(work, "service-index.json")))
    res = {r["@type"]: r["@id"] for r in index["resources"]}
    return res["SearchQueryService/3.5.0"], res["PackageBaseAddress/3.0.0"]


def probe(work):
    search, base = service(work)
    print("search:", search)
    print("flat container:", base)
    for url in (SERVICE_INDEX, search, base):
        host = urllib.parse.urlparse(url).netloc
        print(f"--- robots.txt for {host} ---")
        print(robots(work, url))


def c100_ids(path):
    ids = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if t and not t.startswith("#"):
                ids.add(t.split(",")[0].strip().lower())
    return ids


def has_build_dll(nupkg):
    with zipfile.ZipFile(nupkg) as z:
        names = z.namelist()
    hits = sorted(n for n in names
                  if n.lower().endswith(".dll") and "/" in n and n.split("/")[0].lower() in BUILD_DIRS)
    return hits


def select(work, c100_manifest, cache, out_manifest, out_provenance):
    search, base = service(work)
    excluded = c100_ids(c100_manifest)
    candidates = {}
    for q in QUERIES:
        url = f"{search}?q={urllib.parse.quote(q)}&take={TAKE}&prerelease=false&semVerLevel=2.0.0"
        data = json.loads(fetch(url, os.path.join(work, "search", f"{q}.json")))
        print(f"query '{q}': totalHits={data.get('totalHits')} returned={len(data['data'])}")
        for d in data["data"]:
            key = d["id"].lower()
            if key not in candidates:
                candidates[key] = (d["id"], d["version"], int(d.get("totalDownloads", 0)), q)
    ranked = sorted(candidates.values(), key=lambda c: (-c[2], c[0]))
    print(f"union: {len(ranked)} ids, {sum(1 for c in ranked if c[0].lower() in excluded)} in C100")

    kept, rejected, examined = [], [], 0
    for pid, ver, downloads, q in ranked:
        if len(kept) >= KEEP:
            break
        if pid.lower() in excluded:
            continue
        if not ID.fullmatch(pid) or not VERSION.fullmatch(ver):
            raise Refusal(f"search returned an id or version outside NuGet's character set: {pid!r} {ver!r}")
        examined += 1
        lid, lver = pid.lower(), ver.lower()
        url = f"{base}{lid}/{lver}/{lid}.{lver}.nupkg"
        nupkg = os.path.join(cache, "packages", f"{pid}.{ver}.nupkg")
        fetch(url, nupkg, ZIP_MAGIC)
        try:
            hits = has_build_dll(nupkg)
        except zipfile.BadZipFile:
            rejected.append((pid, ver, downloads, "unreadable .nupkg"))
            continue
        if hits:
            kept.append((pid, ver, downloads, q, len(hits), hits[0]))
        else:
            rejected.append((pid, ver, downloads, "no build-time DLL"))
        print(f"  [{len(kept)}/{KEEP}] {pid} {ver}: {'KEEP' if hits else 'skip'}", flush=True)

    today = datetime.date.today().isoformat()
    with open(out_manifest, "w", encoding="utf-8", newline="\n") as f:
        f.write("# C-build corpus (reachability R2b, S3) - pinned manifest (id,version), one package per line.\n")
        f.write("# Build-time packages: each ships a .dll under analyzers/, build/, buildTransitive/, tasks/ or tools/.\n")
        f.write(f"# Selected {today} from the NuGet V3 search API; provenance and the rule: c-build.provenance.md.\n")
        f.write("# Benign by assumption (download counts), not by proof - see ADR-0021.\n\n")
        for pid, ver, *_ in kept:
            f.write(f"{pid},{ver}\n")

    with open(out_provenance, "w", encoding="utf-8", newline="\n") as f:
        f.write("# C-build corpus provenance\n\n")
        f.write(f"- **Fetched:** {today}, by `fetch_cbuild.py` (reachability R2b, S3).\n")
        f.write(f"- **Service index:** {SERVICE_INDEX}\n")
        f.write(f"- **Search:** `{search}?q=<term>&take={TAKE}&prerelease=false&semVerLevel=2.0.0`, ")
        f.write("terms " + ", ".join(f"`{q}`" for q in QUERIES) + ".\n")
        f.write(f"- **Packages:** `{base}<id>/<version>/<id>.<version>.nupkg` (lower-cased).\n")
        f.write("- **Rule:** union by id; ranked by `totalDownloads` (descending, ties by id); the search result's "
                "version (latest stable); C100 ids excluded; kept if a `.dll` sits under `analyzers/`, `build/`, "
                f"`buildTransitive/`, `tasks/` or `tools/`; stop at {KEEP}.\n")
        f.write(f"- **Counts:** {len(ranked)} distinct ids; {examined} examined; {len(kept)} kept; "
                f"{len(rejected)} rejected.\n")
        f.write("- **Licence:** each package keeps its own licence (see its .nuspec). Only ids and versions are "
                "recorded in the repository; the .nupkg files are cached outside it.\n")
        f.write("- **Download counts** are as of the fetch date and change daily.\n\n")
        f.write("## Kept\n\n| # | Id | Version | Downloads | Query | Build DLLs | First |\n|---|---|---|---|---|---|---|\n")
        for i, (pid, ver, downloads, q, n, first) in enumerate(kept, 1):
            f.write(f"| {i} | {pid} | {ver} | {downloads} | {q} | {n} | `{first}` |\n")
        f.write("\n## Rejected (examined, in rank order)\n\n| Id | Version | Downloads | Reason |\n|---|---|---|---|\n")
        for pid, ver, downloads, why in rejected:
            f.write(f"| {pid} | {ver} | {downloads} | {why} |\n")
    print(f"kept {len(kept)}, rejected {len(rejected)}, examined {examined}")


if __name__ == "__main__":
    try:
        if sys.argv[1] == "probe":
            probe(sys.argv[2])
        elif sys.argv[1] == "select":
            select(*sys.argv[2:7])
        else:
            sys.exit("unknown mode")
    except Refusal as r:
        print(f"STOPPED: {r}")
        sys.exit(2)
