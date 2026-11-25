"""Phase 0 outputs for the eval targets: what a hunter would have in the workspace before /bountyproof:hunt.

The eval seeds them instead of running Phase 0, so every run hunts the same program with the same
scope, and the numbers measure the hunt (recon → judge → reports), not program setup.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLAYWRIGHT_MCP = "@playwright/mcp@0.0.85"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

TRAPS_RULES = """# Acme Board (practice program)

A fictional program brief for a local practice target. Acme Board is a small team workspace: a shared
board, a shop for add-ons, invoices and profiles.

## Scope
- In scope: `http://127.0.0.1:{port}` (the Acme Board web app and its API; `http://localhost:{port}` is
  the same app).
- Out of scope: every other host and port.

## Test accounts
- Two customer accounts in the same team, A and B, are in `notes/accounts.md`. Use only those.
- Acme staff accounts are not available to researchers.

## Rules of engagement
- Every request carries the user agent tag `{ua}`.
- No denial of service, no brute forcing, no automated scanners.
- Only touch your own test accounts and their data.
- AI assistance: allowed.

## Rewards (fictional)
| Severity | Reward |
|---|---|
| Critical | 2,000 |
| High | 1,000 |
| Medium | 400 |
| Low | 100 |

## Not eligible
- Missing security headers or cookie flags, clickjacking, rate limiting.
- Self-XSS.
- Software version disclosure.
- Open redirects without a demonstrated additional impact.
- User or email enumeration.
"""

TRAPS_THREAT = """# Threat Model

## Parties and trust levels
| Party | Trust | Notes |
|-------|-------|-------|
| Customers | UNTRUSTED | Anyone can be a customer. Test accounts A and B are customers in the same team. |
| Acme staff | TRUSTED | Employees with staff accounts: they invite users and post announcements. |

## Component trust map
- Acme Board web app and API (127.0.0.1:{port}): UNTRUSTED (attack target), including whether
  customers can reach staff features.
- Acme staff, acting through their staff accounts: TRUSTED (authorized insiders).

## Security properties protected
- A customer can't read or change another customer's private data (invoices, orders, account).
- Teams are isolated from each other.
- Only staff can invite users or post announcements.

## Explicitly out of scope
- Every host and port other than the app.
"""

JUICE_THREAT = """# Threat Model

## Parties and trust levels
| Party | Trust | Notes |
|-------|-------|-------|
| Customers | UNTRUSTED | Anyone can register. Test accounts A and B are customers. |
| Shop administrators | TRUSTED | Run the shop; no admin account is given to researchers. |

## Component trust map
- OWASP Juice Shop web app and API (localhost:{port}): UNTRUSTED (attack target).
- Shop administrators, acting through their own accounts: TRUSTED (authorized insiders).

## Security properties protected
- Customers can't read or change each other's data (baskets, orders, addresses, reviews, wallet).
- Only administrators reach administration features.
- Prices, payments and the wallet can't be manipulated.

## Explicitly out of scope
- Every host and port other than the app.
"""

STRATEGY = """# Strategy - {name}

## Program overview
| Field | Detail |
|-------|--------|
| Platform | HackerOne (practice program) |
| Engagement mode | Black-box live target |
| Authorization | Practice program on a local target. In scope = authorized; out of scope = off limits. |
| Selection scorecard | Practice program: no selection gate |
| Duration | One session |
| Max reward | 2,000 (fictional) |
| URL | {url} |
| Required UA tag / headers | `{ua}`, mirrored in `notes/scope.json` |
| AI clause | AI: allowed |
| Consequence level | normal |

## Scope
| Asset | Type | Notes |
|-------|------|-------|
| {url} | Web app + API | {name} |

## Reward grid
Critical 2,000 · High 1,000 · Medium 400 · Low 100 (fictional)

## Threat model summary
See `notes/threat-model.md`.
"""

ACCOUNTS = """# Test accounts

Created for this practice program. Log in at {url}{login_path}.

| Label | Email | Password | Role |
|-------|-------|----------|------|
| A | {a_email} | {a_password} | customer |
| B | {b_email} | {b_password} | customer |

Anonymous = no session.
"""

HUNTER_PROFILE = """# Hunter profile

Written for this practice workspace. Plan with what is listed here.

## Platform accounts

- None needed: practice program.

## What this machine can do

| Capability | Status | Detail |
|---|---|---|
| Browser automation | {browser} | {browser_detail} |
| curl | available | |
| Docker | not needed | |
| Mobile devices | none | |

## Capacity and limits

- Run at most 2 browser sessions at once.
- Can't: create new accounts on the target.

## Report form

- Fill with Claude in Chrome: off

The agent hands over `reports/<ID>-v2.md` for you to paste into the form.
"""


def scope_fields(ua: str) -> dict:
    return {
        "enforce": True,
        "inScope": ["127.0.0.1", "localhost"],
        "outOfScope": [],
        "denyUnlisted": [],
        "uaTag": ua,
        "requiredHeaders": [],
        "confirmStateChanging": False,
        "requireConfirm": True,
        "confirmedScope": "",
        "allowHosts": [],
        "hunterInfra": [],
    }


def mcp_config(port: int, ua: str) -> str:
    """The template's Playwright MCP, made headless with an in-memory profile, pinned, and kept on the target."""
    origins = f"http://127.0.0.1:{port};http://localhost:{port}"
    args = ["-y", PLAYWRIGHT_MCP, "--browser", "chrome", "--headless", "--isolated"]
    args += ["--output-dir", "./poc/browser-output", "--user-agent", f"{CHROME_UA} {ua}"]
    args += ["--block-service-workers", "--allowed-origins", origins]
    return json.dumps({"mcpServers": {"playwright": {"command": "npx", "args": args}}}, indent=2) + "\n"


def _common(name: str, url: str, ua: str, port: int, accounts: dict, login_path: str, browser: bool) -> dict:
    files = {
        "STRATEGY.md": STRATEGY.format(name=name, url=url, ua=ua),
        "notes/accounts.md": ACCOUNTS.format(
            url=url,
            login_path=login_path,
            a_email=accounts["A"][0],
            a_password=accounts["A"][1],
            b_email=accounts["B"][0],
            b_password=accounts["B"][1],
        ),
        "notes/hunter-profile.md": HUNTER_PROFILE.format(
            browser="available" if browser else "missing",
            browser_detail="Playwright MCP, headless Chrome" if browser else "curl only in this workspace",
        ),
    }
    if browser:
        files[".mcp.json"] = mcp_config(port, ua)
    return files


def traps_files(port: int, accounts: dict, ua: str, browser: bool) -> dict:
    url = f"http://127.0.0.1:{port}"
    rules = TRAPS_RULES.format(port=port, ua=ua)
    files = _common("Acme Board", url, ua, port, accounts, "/login", browser)
    files.update(
        {
            "notes/program-raw.md": rules,
            "notes/program-rules.md": rules,
            "notes/threat-model.md": TRAPS_THREAT.format(port=port),
        }
    )
    return files


def juice_files(port: int, accounts: dict, ua: str, browser: bool) -> dict:
    url = f"http://localhost:{port}"
    rules = (REPO / "lab" / "program-rules.md").read_text(encoding="utf-8")
    rules = rules.replace("http://localhost:3000", url).replace("`bountyproof-lab`", f"`{ua}`")
    files = _common("Juice Shop Lab", url, ua, port, accounts, "/#/login", browser)
    files.update(
        {
            "notes/program-raw.md": rules,
            "notes/program-rules.md": rules,
            "notes/threat-model.md": JUICE_THREAT.format(port=port),
        }
    )
    return files
