# Memory Index

- [Canonical-name cross-layer parity](project_canonical-name-parity.md) — the CciNames/ModelNames contract, the scratchpad probe recipe, and which divergences are closed vs accepted.
- [Capability map phase 2 gate](project_capability-map-phase2-gate.md) — landed 2026-07-31; the re-derive-the-verdict recipe that actually verified the finding delta.
- [Metadata seam CalledApi contract](project_metadata-seam-calledapi-contract.md) — the "owner!entryPoint" shape is attacker-controlled and arity-blind; re-check on every new seam.
- [CCI signature-decoding project (ADR-0022)](project_cci_signature_decoding.md) — staged FailFast fix plan; Stage 0 + its regression test landed clean, track Stage 1/2 scope
- [Verifying ECMA-335 signature-decoder arms](feedback_ext_signature_decoder_review.md) — check byte consumption + grammar reachability, not just return value
- [Isolating FailFast re-verification](feedback_isolate-failfast-child-process.md) — actually revert/rebuild/run FailFast regression tests as a Bash child process, then restore and diff-check
- [PlatformTypes.Void fix status](project_platformtypes_void_fix.md) — void fix now superseded by the general `BasicType.Equals` corlib-unification (2026-07-27); spoof residual pinned by a test, not just a comment.
- [analysis-net review workflow](project_analysisnet_workflow.md) — spike-doc pattern, re-verify claims by reverting, ADR-0021 FailFast isolation
- [Re-run scratchpad measurement harnesses to verify docs/agent/measurements claims](verify-measurement-harnesses.md) — rebuild+rerun the Probe rather than re-reading tables; works with **no doc at all**, and for numbers pinned only in a source comment.
- [TypeInferenceAnalysis / dataflow track readiness](typeinferenceanalysis-readiness.md) — `PlatformTypes` mscorlib-pinning item now fixed (`BasicType.Equals` widened); still unreached from src/.
- [ext/ comments explaining non-obvious design rationale are acceptable](ext-comment-proportionality.md) — weigh merge-conflict cost against the alternative of the reasoning being lost.
- [CLI exit code vs report footer predicate](project_exit-code-footer-predicate.md) — ADR-0024's invariant has one accepted counterexample (PackageMetadata script findings); `attention` is copied across 4+ sites.
- [Auditing "commutative by construction" claims](feedback_verify-structural-commutativity-claims.md) — partition result arms constant-vs-operand, then trace null/Unknown sentinels through each.
