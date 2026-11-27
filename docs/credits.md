# Credits

bountyproof builds on other people's work. This file lists what came from where, under which
license, and what we changed.

## Claude-BugHunter

- **Author:** Sachin Sharma
- **Repository:** [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter),
  read at commit `9796bee` (2026-11-24)
- **License:** code under the [MIT License](https://github.com/elementalsouls/Claude-BugHunter/blob/main/LICENSE),
  content under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

### Evals (`evals/`)

- **Taken:** the idea of measuring discipline with a local app of look-alike traps next to real
  controls, a neutral prompt and a false-positive rate read together with the true-positive rate
  (`eval/fp_app.py`, `eval/fp_cases.json`, `eval/run_fp.py`); grading against OWASP Juice Shop's own
  challenge oracle (`eval/run_eval.py`).
- **Adapted:** their seven traps (HTML-escaped reflection, reflection inside JSON, a same-origin
  redirect, a canned product lookup, wildcard CORS on public data, a link-only preview, public
  profile fields) and the ambient version banner, re-implemented in `evals/bpevals/trap_app.py`.
- **Changed:** new code throughout. The whole chain is graded (`/bountyproof:hunt` end to end), not a
  single agent's verdict on one endpoint. Eight more traps come from the ways real reports get closed
  (reachability without data, the layer-order 400, own data only, an open redirect with nothing to
  chain, self-XSS, CORS with credentials on public data, already-obtainable data, an insider
  precondition). The controls are proven between two accounts, and the app records server-side what
  really happened. The Juice Shop oracle grades every finding the chain lets through (confirmed,
  refuted or unmodeled) instead of single objectives.

### Scope import and the scope guard (`src/bountyproof/scope_import.py`, `hooks/scope-guard.mjs`)

- **Taken:** `cbh/scope_import.py`, ported to `bountyproof scope import`: the public
  bounty-targets-data source, how each platform's assets are classified, the fail-closed review list,
  the pasted-text mode, the conduct rules found in program text, and a re-import that keeps the rules
  written by hand. Also the holes their scope fixes closed, each turned into a test here: deny rules
  written with a port, a scheme or a trailing dot that matched nothing (#182), redirects out of scope
  (#181), recon hosts that ended up in scope (#198), Unicode and punycode spellings of one host
  (#224, CWE-176), a backslash in the URL authority (#247), out-of-scope hosts lost from pasted
  program text (#235) and agents that weren't told the exclusions (#226). The last three were fixed
  on 25-nov, after the commit read above.
- **Changed:** it writes `notes/scope.json`. Every rule goes through the guard's own parser, which runs
  the same way in Node (the hook) and Python (the CLI), checked against one shared corpus of cases. An
  exact host is only that host, so no regex rules are needed. An excluded wildcard over hosts the
  program lists in scope becomes `denyUnlisted`. White-box workspaces get every program asset out of
  scope. The guard reads commands rather than its own fetcher, so the checks on bare hosts, IPv4 in
  decimal or octal, curl globs, shell variables, redirect flags and target lists are new code, and a
  non-ASCII host is denied outright instead of converted.

The adapted parts carry this notice:

```text
MIT License

Copyright (c) 2026 Sachin Sharma

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## OWASP Juice Shop

The demo lab and the juice suite run [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
(Björn Kimminich and contributors, MIT License) from its published Docker image. Nothing of it is
copied into this repository.
