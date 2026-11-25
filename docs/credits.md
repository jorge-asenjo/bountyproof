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
