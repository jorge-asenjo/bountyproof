# CVSS 3.1 Conservative Scoring

Principle: ALWAYS score conservatively. Let the triager bump it up.

| Scenario | Vector | Score |
|----------|--------|-------|
| Info disclosure, no auth | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Info disclosure, low priv | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 |
| CSRF state change | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N | 4.3 |
| Stored XSS, low priv | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| RCE, low priv | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 |
| Path traversal read | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| SSRF internal | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 |
| IDOR read, sequential/predictable IDs | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 |
| IDOR read, non-guessable IDs (UUIDv4, opaque token) | AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N | 3.1 |

When in doubt:
- PR: LOW not NONE (unless truly unauth)
- C/I/A: LOW not HIGH (unless full read/write/crash)
- S: UNCHANGED unless vuln escapes its context
- AC: HIGH when the attacker needs something they can't get at scale (victim's random UUID, a race
  window, a specific config). Only `AC:L` for IDs if you SHOW how victims' IDs are obtained
  (sequential, listed in another response, leaked in URLs) — and say where in the report.
- Score only what you verified: don't pick `PR:N`, `UI:N` or `C:H` you didn't actually test.
