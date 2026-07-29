---
name: reference-pdf-books
description: PDF tooling — the Read tool CAN render reference PDFs (worked 2026-07-17); mupdf/mutool in bin/ is the fallback. Supersedes the earlier "poppler missing" note.
metadata:
  type: reference
---

Reading PDFs in this repo:
- The **Read tool renders PDFs** — confirmed 2026-07-17 by reading `reference/articles/Inside the
  NuGet package hacker's toolset _ RL Blog.pdf` (13.9 MB, ~23 pages) successfully. Pass a `pages`
  range for large files (>10 pages requires it). **This supersedes the earlier note that PDFs were
  unreadable** (that claim — pdftoppm/poppler missing — is stale or was specific to the large
  `reference/books/static*.pdf` files; retry those via mupdf below before assuming they're unreadable).
- Fallback / programmatic PDF work: the repo ships **`bin/mutool.exe`, `bin/mupdf.exe`,
  `bin/mupdf-gl.exe`** — e.g. `bin/mutool draw -F txt <pdf>` to dump text, `bin/mutool extract` for
  embedded images.
- **2026-07-25:** the Read tool's PDF path failed here with *"pdftoppm is not installed"* (poppler
  absent), so it is **not** reliably available — go straight to `bin/mutool.exe draw -F txt -o out.txt
  <pdf>` and grep the dump. That worked on a 213-page thesis (313 k chars) and is far cheaper than
  paging images. Note a PDF's real page count may exceed what the file-preview reports.
- **The page-count discrepancy is large, not cosmetic** (2026-07-29): the tool preview reported
  **49 pages** for `reference/books/ECMA-335_6th_edition_june_2012.pdf`; it is actually **574**.
  Get the truth with `bin/mutool.exe info <pdf>`, then `draw -F txt` the whole thing and Grep it.
  ⚠️ `/tmp/...` in Bash is NOT a path the Grep/Read tools accept — convert with `cygpath -w` first.
  Table dumps lose grid alignment (empty cells become blank lines) but preserve cell text in
  row-major order, so a normative table is still recoverable — just read the surrounding prose to
  confirm the column headers before trusting the reconstruction.

Key papers read: `reference/papers/tesis_n6970_Zoppi.pdf` — the **analysis-net author's PhD thesis**
(Zoppi, UBA 2019); authoritative on the IR ladder, the `Disassembler` stage and the points-to analysis.
See [[analysisnet-disassembler-gaps]] and the research journal.

Research workflow: there is **no `researcher`/general-purpose subagent** in this session (confirmed
2026-07-17 — only code-reviewer/debugger/dotnet-implementer/test-engineer). Do web/article research
**in-thread** (curl for web, Read for local PDFs) and write findings to `docs/agent/research/`. See
[[research-journal]].
