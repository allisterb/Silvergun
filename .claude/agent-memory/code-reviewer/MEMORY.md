# Memory Index

- [Canonical-name cross-layer parity](project_canonical-name-parity.md) — the CciNames/ModelNames contract, the scratchpad probe recipe, and which divergences are closed vs accepted.
- [Capability map phase 2 gate](project_capability-map-phase2-gate.md) — legacy StartsWith over-matches that will silently vanish when CapabilityAnalysis is wired onto the map.
- [Metadata seam CalledApi contract](project_metadata-seam-calledapi-contract.md) — the "owner!entryPoint" shape is attacker-controlled and arity-blind; re-check on every new seam.
- [CCI signature-decoding project (ADR-0022)](project_cci_signature_decoding.md) — staged FailFast fix plan; Stage 0 + its regression test landed clean, track Stage 1/2 scope
- [Verifying ECMA-335 signature-decoder arms](feedback_ext_signature_decoder_review.md) — check byte consumption + grammar reachability, not just return value
- [Isolating FailFast re-verification](feedback_isolate-failfast-child-process.md) — actually revert/rebuild/run FailFast regression tests as a Bash child process, then restore and diff-check
