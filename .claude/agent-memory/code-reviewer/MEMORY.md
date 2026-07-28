# Memory Index

- [Canonical-name cross-layer parity](project_canonical-name-parity.md) — the CciNames/ModelNames contract, the scratchpad probe recipe, and which divergences are closed vs accepted.
- [Capability map phase 2 gate](project_capability-map-phase2-gate.md) — legacy StartsWith over-matches that will silently vanish when CapabilityAnalysis is wired onto the map.
- [Metadata seam CalledApi contract](project_metadata-seam-calledapi-contract.md) — the "owner!entryPoint" shape is attacker-controlled and arity-blind; re-check on every new seam.
- [CCI signature-decoding project (ADR-0022)](project_cci_signature_decoding.md) — staged FailFast fix plan; Stage 0 + its regression test landed clean, track Stage 1/2 scope
- [Verifying ECMA-335 signature-decoder arms](feedback_ext_signature_decoder_review.md) — check byte consumption + grammar reachability, not just return value
- [Isolating FailFast re-verification](feedback_isolate-failfast-child-process.md) — actually revert/rebuild/run FailFast regression tests as a Bash child process, then restore and diff-check
- [PlatformTypes.Void fix status](project_platformtypes_void_fix.md) — what's fixed, what's accepted risk, what's still out of scope
- [analysis-net review workflow](project_analysisnet_workflow.md) — spike-doc pattern, re-verify claims by reverting, ADR-0021 FailFast isolation
- [Re-run scratchpad measurement harnesses to verify docs/agent/measurements claims](verify-measurement-harnesses.md) — don't just re-read the doc's tables, rebuild+rerun the Probe if it's still in scratch.
- [TypeInferenceAnalysis / dataflow track readiness](typeinferenceanalysis-readiness.md) — ongoing prerequisite-by-prerequisite unblocking effort; not reachable from src/ yet.
- [ext/ comments explaining non-obvious design rationale are acceptable](ext-comment-proportionality.md) — weigh merge-conflict cost against the alternative of the reasoning being lost.
