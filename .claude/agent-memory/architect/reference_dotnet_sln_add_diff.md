---
name: dotnet-sln-add-rewrites-platforms
description: dotnet sln add on this repo rewrites the whole ProjectConfigurationPlatforms section (injects x64/x86 for every project) — hand-edit src/Silvergun.sln instead
metadata:
  type: reference
---

**Do not use `dotnet sln add` to register a project in `src/Silvergun.sln`.** On SDK 10.0.101 it
rewrites the entire `ProjectConfigurationPlatforms` section, injecting `Debug|x64`, `Debug|x86`,
`Release|x64` and `Release|x86` mappings for **every existing project**, none of which the solution
had before. Observed 2026-08-03.

**Why it matters:** the command succeeds and the project is correctly registered, so the damage is
invisible unless someone reads the diff. A one-project addition turns into a whole-file rewrite that
is easy to commit by accident and painful to review or revert later.

**How to apply:** register a new project by a minimal hand edit replicating the three blocks used by
the nearest sibling entry:

1. the `Project(...) ... EndProject` declaration (project-type GUID
   `{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}` for these test projects, plus a fresh project GUID),
2. four `ProjectConfigurationPlatforms` lines — `Debug|Any CPU` and `Release|Any CPU`, each
   `ActiveCfg` and `Build.0`. **Any CPU only**; this solution has no x64/x86 rows,
3. one `NestedProjects` line mapping the new GUID to the `Tests` solution folder
   `{F3CA7A48-1B99-4555-84CA-54FFFB3762EF}`.

A correct single-project registration is **+7 lines**. Verify with `dotnet sln src/Silvergun.sln
list` and `git diff --stat src/Silvergun.sln` — not with a build, since
`dotnet build src/Silvergun.sln` fails on `Silvergun.Vsix` by design.

Convention worth keeping: **every** fixture/probe project under `tests/` is registered in this
solution. A new one that is not registered is an inconsistency, not a design choice.
