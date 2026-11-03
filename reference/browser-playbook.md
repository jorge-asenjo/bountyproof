# Browser Playbook (Playwright MCP) — how Claude drives the browser

Goal: the **human only does login + captcha + 2FA, once.** Everything else (navigate, click, fill,
read network, replay/modify requests, screenshot evidence) is driven by the Claude session through
the Playwright MCP server wired in `.mcp.json`. No more "capture this in Chrome's Network tab for me".

## Two browsers
| | Playwright (`.mcp.json`) | Claude in Chrome |
|---|---|---|
| For | testing the target | the platform's report form (Phase 4d) |
| Profile | its own, `./tools/browser/profile` | the human's Chrome, with their sessions |
| Program UA tag | set in `.mcp.json` | none |
| Scope guard | every navigation checked | every navigation checked; target hosts blocked; a click described as a submit asks the human |

Keep them apart. The human's own Chrome carries their personal sessions and no program UA tag, so it
never touches the target. Everything below is about the Playwright browser.

## Prerequisites (one-time, per machine/engagement)
1. `.mcp.json` is present (template ships it). It launches **headed real Chrome** with a **persistent
   profile** (`./tools/browser/profile`), the program UA, and OOS hosts blocked.
2. **Restart Claude Code** so it loads the `playwright` MCP server. Confirm with `/mcp` or `claude mcp list`.

## The login-once flow
1. The session calls a browser tool (e.g. `browser_navigate` to the target). Chrome opens with the
   persistent profile.
2. **User logs in** in that window: credentials + captcha + SMS/2FA. This is the ONLY manual step.
   Tell the user exactly what to do, then wait.
3. The profile persists the session. Every later run reuses it — no re-login until the session
   actually expires (then repeat step 2, ~1 min).

## Core MCP tools (Playwright MCP)
- `browser_navigate` / `browser_navigate_back` — go to URLs (in-scope only).
- `browser_snapshot` — accessibility tree of the page (preferred over screenshots for reasoning).
- `browser_click` / `browser_type` / `browser_fill_form` / `browser_select_option` — drive forms/flows.
- `browser_network_requests` — **the key one**: returns all requests/responses (URL, method, status,
  headers, bodies) captured this session. This replaces manual Network-tab capture.
- `browser_evaluate` — run JS in page context (read tokens from JS state, inspect SPA internals).
- `browser_take_screenshot` — saves to `./poc/browser-output` for PoC evidence.
- `browser_console_messages` — console errors (CSP report-only violations, JS errors).

## How to hunt with it (maps to Phases 2-3)
1. **Walk the flow** with navigate/click/fill as the authenticated user. Let it render naturally —
   interactive driving is slow, which keeps you under the rate limit.
2. **Harvest the API** via `browser_network_requests`: record real endpoints, params, object IDs,
   tokens (CSRF tokens, signed IDs, one-time link tokens) into `notes/case-file.md` (Facts + Hypotheses).
3. **Form hypotheses** (Phase 2). For object-level authz (IDOR/BOLA): note the object IDs seen for
   account A; you'll replay them as account B.
4. **Validate** (Phase 3, separate role): replay/modify the captured request as a different actor.
   Two ways:
   - In-browser as account B (switch profile or use `browser_evaluate`/a second context), OR
   - Export the request and replay with `curl` using account B's cookies (often cleaner for
     pure-API IDOR). Run the **negative control first** (account A's own object) to establish baseline.
5. **Capture evidence**: `browser_take_screenshot` + the matching `browser_network_requests` entry
   (request + response). Drop refs into the dossier. Then run `prompts/03b-evidence-judge.md`.

## Rules & guardrails (live targets)
- Stay in scope. OOS hosts are blocked in `.mcp.json`, but YOU still must not navigate OOS.
- Respect the program's rate limit (e.g. ≤10 req/s) and "gentle automation only" — no scripted
  spraying/bruteforce through the browser either.
- Keep the program UA (set in `.mcp.json`). Don't strip it.
- Non-destructive only: read/observe, use your own test accounts and any test objects the program
  designates.
- Captcha/2FA are sentinels — never try to auto-solve or bypass them. That's abuse.

## When curl replay is better than the browser
For pure JSON API probing (IDOR sweeps across object IDs), exporting cookies once and looping
`curl` is faster and easier to rate-limit precisely than clicking. Use the browser for
JS-rendered / multi-step / CSRF-token flows; use curl for raw API replay. Both feed the same case file.
On Windows PowerShell use `curl.exe`.
