---
name: dataset-corpus-initiative
description: Building a labeled benign/malicious NuGet package+code corpus is a planned near-term initiative (prerequisite for any calibrated risk score)
metadata:
  type: project
---

Assembling a **labeled corpus of benign + malicious NuGet packages and code** is a committed
near-term initiative. The user has their own ideas on how to source/build it and wants to tackle it
soon — parked 2026-07-17 to revisit **after** the ReversingLabs YARA-rules + Spectra-Assure-comparison
task.

**Why:** every accuracy/risk-scoring claim is uncalibrated without ground truth. When the OSSGadget
risk-score port was assessed, the honest conclusion was "no composite is calibratable without a
labeled malicious/benign NuGet corpus, which we don't have" — this corpus is the missing prerequisite.
Relates to [[risk-scoring]] deferral (`docs/agent/research/risk-scoring-and-sandboxing.md`).

**How to apply:** when risk scoring, detection accuracy, or false-positive rates come up, flag that the
corpus is the gating prerequisite and don't over-claim numbers until it exists. When we return to it,
the user drives the sourcing approach (ask them). A validation corpus also feeds YARA-rule tuning and
capability-catalog coverage checks.
