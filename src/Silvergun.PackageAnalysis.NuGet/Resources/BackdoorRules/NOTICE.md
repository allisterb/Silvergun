# Embedded backdoor rulesets — third-party attribution

The JSON ruleset files in this directory are Application Inspector rules copied
verbatim from the **OSSGadget** project (Microsoft), which detects malicious /
backdoor patterns in package content.

- Source project: `microsoft/OSSGadget` (https://github.com/microsoft/OSSGadget)
- Source path in this repo's reference tree:
  `reference/projects/OSSGadget-main/src/Shared.CLI/Resources/BackdoorRules/`
- Files copied (unmodified): `backdoor_signatures.json`, `code_execution.json`,
  `crypto_currency.json`, `data_exfiltration.json`, `dependency_confusion.json`,
  `ioc.json`, `lolbas.json`, `obfuscation.json`, `pastebin.json`,
  `reverse_shell.json`.
- Copy approved by the project owner on 2026-07-17 (see task
  `docs/agent/tasks/appinspector-script-rules.md` and ADR
  `docs/agent/decisions/0012-script-content-rule-scanning.md`).

These files are embedded as resources and loaded at runtime by
`ScriptRuleScanner` via the Application Inspector RulesEngine.

## License (MIT)

Copyright (c) Microsoft Corporation. All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
