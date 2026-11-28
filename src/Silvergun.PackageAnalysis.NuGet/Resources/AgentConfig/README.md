# Agent-configuration paths: provenance

`agent_config_paths.json` lists paths that control what an AI coding agent loads, is told, or may run. MCP task S4
(`docs/agent/tasks/mcp-server.md`) reports a package build file that writes to or names one of them.

- **Starting set:** `docs/agent/tasks/agent-config-write-rule.md`.
- **Verification:** each entry was checked against the agent vendor's official documentation on 2026-11-27. The URL is
  in the entry's `source`. Only documentation pages were read, at about one request per second, each page once. No
  site refused or challenged a request.
- **Unverified entries:** these ship with `"status": "unverified"` and `source: null`. They are never given an invented
  source:
  - `.github/chatmodes/`: not on the current VS Code pages, which describe `.github/agents/` instead;
  - `.codeium/windsurf/mcp_config.json`: the current Windsurf (Devin Desktop) page names only `.devin/` and
    `~/.config/devin/` files.
- **Collapsed entries:** where the docs name several files under one agent folder, the list has the folder:
  - `.claude/` covers `settings.json`, `settings.local.json`, `skills/`, `agents/`, `commands/`, `rules/`,
    `output-styles/`, `workflows/` and `agent-memory/`. Hooks live in the settings files.
  - `.cursor/`, `.gemini/`, `.kiro/`, `.amazonq/`, `.devin/` and `.opencode/` are collapsed the same way.
- **Left out:** `.vscode/` and `.github/` on their own, which benign build files use often. Only the agent files under
  them are listed.

The list is data, original to this project. A token added here needs its source URL and fetch date in the same change.
