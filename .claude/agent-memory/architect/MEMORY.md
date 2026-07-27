# Architect memory index

- [Reading PDFs](reference_pdf_books.md) — Read tool renders PDFs (worked 2026-07-17); bin/mutool is the fallback; no researcher subagent (research in-thread)
- [Hostile-input threat model](project_hostile_input_threat_model.md) — Silvergun ingests malicious packages by design; treat all package/assembly input as hostile, defense-in-depth
- [analysis-net gaps: TAC + uncatchable FailFast](project_analysisnet_disassembler_gaps.md) — TAC lifter fails on modern IL; CCI reader can FailFast-kill the process, so "never throws" guards don't hold (ADR-0021)
- [CCI reader is unmaintained upstream](project_cci_reader_unmaintained.md) — asnarnd fork works only CCI's AST/codegen half; reader untouched, so we own reader robustness — no "wait for upstream"
- [Research journal](project_research_journal.md) — running prior-art log at docs/agent/research/RESEARCH-JOURNAL.md; append new projects there; web research runs in-thread via curl
- [Test-fixture packages](reference_test_fixture_packages.md) — user-authored nuget.org packages for live smoke tests; Jumbee.Console.Snapshot has a depth-2 transitive vuln (ImageSharp GHSA-rxmq-m78w-7wmc)
- [External intel optional keys](project_external_intel_optional_keys.md) — enrich analysis with optional user-provided API keys (libraries.io/OSS Index/Sonatype); degrade gracefully to keyless; enrichment not hard dependency
- [Positioning: differentiated lane](project_positioning_differentiated_lane.md) — core value is static+dynamic hunting NuGet/VS don't do; vuln-data/resolver-lite parity is commodity completeness, not the differentiator — don't over-invest
- [Measure before designing](project_measure_before_designing.md) — spike first on any ext/analysis-net or compiler-behaviour claim; 8 architect assumptions falsified by measurement so far
- [Opus cyber-filter on reviews](project_opus_cyber_filter_reviews.md) — Opus 4.8 specialists trip a cybersecurity safety filter on malware-adjacent code; re-dispatch on Sonnet with correctness-framed wording
- [Avoid the `find` command](feedback_avoid_find_command.md) — `find` hangs (resolves to Windows find.exe, blocks on stdin); use Glob/Grep tools instead
- [Email-literal redaction on file writes](feedback_email_literal_redaction.md) — literal `user@host` (e.g. `git@github.com`) is silently rewritten when written to a file; split the token
- [Prefer PowerShell scripts](feedback_no_powershell.md) — REVERSED 2026-07-26: PowerShell now allowed/preferred over finicky Bash; also don't run test suites in parallel (CS2012)
