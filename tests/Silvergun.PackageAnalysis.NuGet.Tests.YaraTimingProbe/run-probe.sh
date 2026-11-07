#!/bin/bash
# Deterministic driver for the in-process YARA timing probe
# (docs/agent/tasks/yara-inprocess-timing-probe.md).
#
#   bash tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe/run-probe.sh
#
# Every scan is watchdogged at 120 s inside the probe. A watchdog hit is TERMINAL for that process
# (a blocked native yr_rules_scan_fd cannot be cancelled) and exits 2, so the plan below is a
# SEQUENCE OF PROCESSES: run 1 writes the TSV, every later run appends to it. Runs that are expected
# to exit 2 are marked; that is data, not failure.
#
# Wall clock: roughly 11 minutes, most of it the five 120 s watchdog waits.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXE="$ROOT/tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe/bin/Release/net10.0-windows/win-x64/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe.exe"

if [ ! -f "$EXE" ]; then
    echo "Build first: dotnet build tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe.csproj -c Release -r win-x64"
    exit 1
fi

run() {                       # run <description> <args...>
    local desc="$1"; shift
    echo
    echo "########## $desc"
    echo "########## args: $*"
    "$EXE" "$@"
    local rc=$?
    echo "########## exit=$rc"
    return $rc
}

# 1. The spec's plan, full ruleset. E4 at N=309 is expected to hit the watchdog and exit 2, which
#    ends this process before E7/E3/E2 - hence run 2. NOTE: no --append, this run creates the TSV.
run "spec plan, full ruleset (expect exit 2 at E4 N=309)"

# 2. Resume E7/E3/E2 at the largest E4 subset that completed (128 rule files).
run "E7/E3/E2 at the largest ruleset that completed" \
    --append --experiments E1,E7,E3,E2 --max-rules 128

# 3. E3 at the FULL ruleset: does the pathology need a big input? (H1 vs H2/H5 at the bad ruleset.)
#    Expected: 1 B completes, 1 KB hits the watchdog -> exit 2.
run "E3 size ladder at the full ruleset (expect exit 2)" \
    --append --experiments E1,E3

# 4. Prefix bisect of the rule-count cliff between the fast N=128 and the timing-out N=309.
#    One process per probe because a timeout is terminal. exit 2 == that prefix is pathological.
lo=128
hi=309
while [ $((hi - lo)) -gt 1 ]; do
    mid=$(( (lo + hi) / 2 ))
    run "bisect prefix N=$mid (fast=$lo, slow=$hi)" --append --experiments E4 --subsets "$mid"
    if [ $? -eq 2 ]; then hi=$mid; else lo=$mid; fi
done
echo "########## BISECT: prefix $lo completes, prefix $hi does not; trigger is rule file index $((hi - 1))"

# 5. Isolate that one rule file. Expected: exit 2 even though it compiles ZERO rules.
run "isolate the trigger rule file (expect exit 2)" \
    --append --experiments E4 --subsets 1 --rule-offset $((hi - 1))

# 6. Control A - a virgin Compiler with no AddRuleString at all, GetRules(), scan. Separates
#    "an empty ruleset is slow" from "a ruleset built from an ERRORED compiler is slow".
run "control A: empty compiler, zero rules" \
    --append --experiments E4 --subsets 0

# 7. Control B - one ordinary rule file adjacent to the trigger, to rule out a positional artefact.
run "control B: single good rule file next to the trigger" \
    --append --experiments E4 --subsets 1 --rule-offset "$hi"

# 8. Size knee of the pathological ruleset. Expected: a handful of bytes is enough. Exit 2.
run "size knee with the trigger rule file only (expect exit 2)" \
    --append --experiments E1,E3 --max-rules 1 --rule-offset $((hi - 1)) \
    --sizes 2,4,8,16,32,64,128,256,512,1024

# 9. H4 at the PATHOLOGICAL ruleset: E7 only ever runs at a healthy rule count above, which cannot
#    tell you whether ScanMemory would dodge the pathology. It does not - ScanMemory is tried first
#    and hits the watchdog too, so yr_rules_scan_mem is affected exactly like yr_rules_scan_fd.
run "E7 against the trigger rule file (expect exit 2 on ScanMemory)" \
    --append --experiments E1,E7 --max-rules 1 --rule-offset $((hi - 1))

echo
echo "TSV: $ROOT/data/results/yara-inprocess-timing-2026-08-21.tsv"
