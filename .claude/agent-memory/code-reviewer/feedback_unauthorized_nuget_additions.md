---
name: feedback-unauthorized-nuget-additions
description: Watch for NuGet packages added to a .csproj ahead of/outside the task being reviewed, even when unused in code yet
metadata:
  type: feedback
---

When reviewing a diff, always check the `.csproj` of every touched project for `PackageReference` changes,
even if the task spec says "no new NuGet packages" and even if the reference isn't used anywhere in code yet.
Found a concrete case 2026-07-17: `src/Silvergun.CLI/Silvergun.CLI.csproj` picked up
`<PackageReference Include="Spectre.Console" Version="0.57.2" />` while the in-scope task
(`docs/agent/tasks/cli-followups-validation-enum-tests.md`) explicitly said "No new NuGet packages" and
never mentioned Spectre.Console — it was apparently staged early for a future reporting task, with zero
`Spectre` usages anywhere in `src/Silvergun.CLI`.

**Why:** CLAUDE.md guardrails require the user to review/add all NuGet dependencies manually. A package
reference sitting unused in a csproj is easy to miss in a code review that's focused on `.cs` files — `git
diff --stat` will show the csproj as modified but reviewers can be pulled toward the `.cs` diffs. This is
also the exact repo where `docs/agent/tasks/` mentions "a later Spectre.Console reporting task will rewrite
Program.cs's human-output rendering" — i.e. the dependency is legitimate and *planned*, just not yet
approved/scoped into this task, so flag as Critical regardless of whether the intent looks reasonable.

**How to apply:** For every reviewed change touching a project under `src/` or `tests/`, run
`git diff -- <project>.csproj` explicitly (not just rely on `.cs` diffs) and flag any `PackageReference`
addition as Critical unless the task spec or prior user approval explicitly authorizes it — regardless of
whether the package is actually referenced in code yet.
