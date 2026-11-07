# Measured runs

Results of Silvergun's measurement runs: each date-stamped `.md` report and, where there is one, the `.tsv` beside it.
The corpora they ran over are pinned in [`../corpus/`](../corpus/), and each report records its manifest and that
manifest's hash. A report describes the code and the package versions of its date; later runs do not update it.

- **Written by:** the benign-corpus harness (`tests/Silvergun.CodeAnalysis.IL.Tests.BenignCorpusHarness`, whose
  default `--out` is this folder), the YARA timing probe (`tests/Silvergun.PackageAnalysis.NuGet.Tests.YaraTimingProbe`),
  and the measurement tasks each report names.
- **`c-build/`:** the reachability report over the build-time corpus (`../corpus/c-build.manifest`), whose file names
  would otherwise collide with the C100 report of the same date. `reachability-combine-<date>.md` judges the two
  together.
- **Third-party data:** package ids, versions, entry names and finding counts derived from public nuget.org packages,
  each under its own licence. No package file is stored here.
- **Redaction (2026-11-07):** these files were moved from the project's internal notes, and in moving them local
  profile paths were rewritten: a Windows local app-data root became `%LOCALAPPDATA%`, a Windows user profile became
  `%USERPROFILE%`, and a Linux home directory became `~`. In-repo references to these files were repointed from
  `docs/agent/measurements/` to `data/results/`. No other text and no number changed. A length or count that a report
  gives for such a path refers to the original path. The harness now writes reports this way itself.
- **Re-runs write here:** the harness's default `--out` is this folder, so a run with the same date overwrites a
  committed report, and the YARA timing probe appends to its committed `.tsv`. Pass `--out` (or a scratch TSV) for a
  run that is not meant to replace the record.
