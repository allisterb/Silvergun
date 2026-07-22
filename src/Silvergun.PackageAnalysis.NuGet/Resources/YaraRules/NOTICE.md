# YARA rules — third-party attribution

This project embeds YARA malware-detection rules from the **ReversingLabs YARA Rules**
project, used under the MIT License. The rules are embedded *by link* from the
`ext/reversinglabs-yara-rules` git submodule (they are never copied into `src/`); update
them by pulling the submodule. See ADR 0016 (`docs/agent/decisions/0016-yara-scanning.md`).

- Project: ReversingLabs YARA Rules
- Source (fork): https://github.com/allisterb/reversinglabs-yara-rules
- Upstream: https://github.com/reversinglabs/reversinglabs-yara-rules
- Pinned submodule commit: `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84`
- License: MIT

```
Copyright (c) 2020 ReversingLabs

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

The full upstream license text is in `ext/reversinglabs-yara-rules/LICENSE`.

Rules placed under `Resources/YaraRules/Custom/` are Silvergun's own and are compiled
alongside the ReversingLabs set.
