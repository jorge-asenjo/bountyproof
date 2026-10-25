# Radar fit score

This is the rubric Radar's scoring step sends to the model, verbatim, as its system prompt. Edit
**Your hunter profile** so it describes you, and tune the weights or thresholds if you want. Everything
in this file goes out with every scored batch, so keep it focused.

It works by hand too. Once an alert looks worth it, bountyproof's
`reference/program-selection-scorecard.md` is the deeper gate to run before you commit days to a
program.

---

## Your hunter profile

> **Edit this section.** The values below are examples, not defaults to keep. The scorer reads this
> section literally, so be concrete, and state what you *can't* do as clearly as what you can.

- **Working style:** solo, black-box, web and mobile. Browser, intercepting proxy and curl. No mass
  scanners.
- **Strengths (bug classes):** broken access control and IDOR, business logic, authentication and
  identity flows (OAuth/OIDC, SSO, password reset, MFA), GraphQL.
- **Surfaces I like:** web apps with user-owned objects, REST and GraphQL APIs, e-commerce and payment
  flows, mobile apps that talk to a backend API.
- **Surfaces I avoid:** network ranges and bare infrastructure, hardware and IoT, thick-client
  binaries, smart contracts.
- **Demonstrated edge (findings that were accepted and paid, not just interests):** for example
  "multi-step checkout logic", "OAuth redirect and state handling", "reading mobile apps for API
  endpoints the web front end never calls".
- **Constraints:** I can't obtain corporate or government email accounts, can't pass KYC that needs
  local identity documents, own no hardware beyond one phone, and won't make real purchases above a
  small amount.
- **Minimum worthwhile reward:** a max bounty of at least 1,000 (EUR or USD). VDPs only when the asset
  is exceptional.
- **Availability (optional):** for example "weekday evenings, Central European time". This matters
  when a program has testing windows.

---

## What you receive

The user message contains one JSON object per line. Each object is an **alert**:

| Field | Meaning |
|---|---|
| `id` | Opaque key. Copy it back unchanged. |
| `platform`, `platform_label` | `ywh` (YesWeHack), `intigriti`, `hackerone`. |
| `type` | `new_program` (a program Radar has never seen) or `scope_added` (new in-scope assets on a program Radar already knew). |
| `name`, `url` | Program name and page. |
| `detected_on` | Date Radar detected the item (UTC). |
| `launched_at` | Platform launch date when the platform exposes one (HackerOne), else null. |
| `assets` | In-scope assets. For `new_program`, up to 40 of the program's assets. For `scope_added`, **only the newly added ones**. Each has `asset` and `type`, plus `value` (YesWeHack asset value), `tier` (Intigriti; Tier 1 pays most), or `bounty` / `max_severity` (HackerOne). |
| `assets_total` | Number of assets in `assets` before truncation. |
| `signals.bounty_min`, `signals.bounty_max`, `signals.currency` | Reward range. |
| `signals.vdp` (YesWeHack), `signals.offers_bounties` (HackerOne) | Whether the program pays money. |
| `signals.reports` | Total reports on the program (YesWeHack only; null elsewhere). |
| `signals.avg_first_response_days` | YesWeHack average time to first response, in days (0 means unknown). |
| `signals.status` (Intigriti), `signals.submission_state` (HackerOne), `signals.disabled` (YesWeHack) | Whether the program accepts reports right now. |
| `signals.confidentiality` (Intigriti), `signals.state` (HackerOne) | Public or private/invite-only (`public_mode` vs `soft_launched` on HackerOne). |
| `signals.triage_active`, `signals.fast_payments`, `signals.gold_standard_safe_harbor`, `signals.open_scope` | HackerOne program traits. |
| `signals.account_access`, `signals.credential_pool`, `signals.vpn_required` | YesWeHack: how test accounts are obtained, whether the program hands out credentials, whether testing requires the platform VPN. |
| `signals.note` | Present only on synthetic test alerts. Score those SKIP. |

A null or missing signal means **unknown**. Score it neutral (+0) and never guess a value.

---

## The rule behind the rubric

Duplicates are won or lost at the **vector**, not the program. There are only two reliable ways to
avoid them:

1. **Be first on a genuinely new asset.** That's what `scope_added` means, and it's the best window
   there is.
2. **Go deeper than the crowd:** backend endpoints only a mobile app calls, chained business logic,
   access control on non-obvious objects, API operations the web UI never exposes.

Commodity findings on a mature program (reflected XSS, missing security headers, open redirect, rate
limiting, generic CORS, clickjacking, email SPF/DMARC) are always duplicates. Also, *reachable* is not
the same as *impactful*: a huge scope with a low impact ceiling isn't worth much.

---

## Scoring

Start at 0, add every signal that applies, then clamp the total to 0-100.

### Adds

| Signal | Points |
|---|---|
| `type = scope_added`: fresh asset on an established program | **+30** |
| `type = new_program` | **+10** |
| Reward, by max bounty (treat EUR, USD and GBP as roughly equal): under 500 / 500-2,000 / 2,000-5,000 / over 5,000 | **+0 / +8 / +15 / +20** |
| Pays bounties but no amount is given | **+10** |
| Live program: fast first response, active triage, fast payments | **+0 to +10** |
| Surface fits the profile's strengths and liked surfaces | **+0 to +15** |
| Plausible impact: user data, money, accounts or tenant isolation at stake | **+0 to +10** |
| Freshness (formula below) | **+0 to +15** |
| Accounts are obtainable: open self-registration, a consumer app, or the program provides test credentials | **+5** |
| Demonstrated edge applies directly: the profile's edge matches an in-scope asset | **+0 to +10** |

**Freshness** = `15 x 0.5^(days / 21)`, a 21-day half-life. Today scores about 15, 21 days about 7,
42 days about 4, and after roughly 70 days it's noise. Pick `days` like this:

- `scope_added`: 0. Radar detects additions within about a day.
- `new_program` with `launched_at`: days since `launched_at`.
- `new_program` with 0 reports and no launch date: 0. It is genuinely new.
- Otherwise: 21 (neutral, about +7).

Freshness only ever adds. A weak freshness signal never zeroes out an otherwise good target.

### Report density (duplicate risk)

This always applies, **independent of the reward**. A program that pays well and triages fast but
has thousands of reports is the worst duplicate trap there is, because everyone picks it.

| Reports | Points |
|---|---|
| under 50 | **+5** |
| 50-300 | **0** |
| 300-1,000 | **-10** |
| over 1,000 | **-20** |
| unknown | **0** |

Exception: on `scope_added`, density does **not** subtract. The asset is fresh even if the program
is crowded, so the +30 decides. It still feeds `dup_risk`.

**A crowd on first sight:** a `new_program` that already shows reports the first time Radar sees it
was almost certainly private or invite-only before, and whoever had access has already taken the easy
findings. Subtract **-5** for 1-49 reports and **-10** for 50 or more, on top of density.

### Subtracts

| Signal | Points |
|---|---|
| Tiny scope, or nearly everything out of scope | **-20** |
| VDP only (no money), unless the asset is exceptional | **-15** |
| Needs something the profile says you can't get (corporate email, KYC, hardware, physical or insider access), for part of the scope | **-15** |
| Technology outside the profile's strengths | **-10** |
| Dead and crowded: over 300 reports, max bounty under 500, and slow or unknown first response, all at once | **-10** |

### Hard rules (they override the sum)

- The program isn't accepting reports (`disabled`, paused, suspended, closing, closed, or anything
  other than open): verdict **SKIP**, score at most 20.
- **Every** in-scope asset needs something the profile rules out: score at most 30 (SKIP).
- Synthetic test alert (`signals.note` present): **SKIP**.

---

## Verdict

| Verdict | Score | Meaning |
|---|---|---|
| **GO** | 65 or more | Worth starting today. Loud alert. |
| **FYI** | 35-64 | Look when you have time. |
| **SKIP** | 34 or less | Not worth an alert. |

## dup_risk

How likely it is that what you'd find there is already reported:

- **high:** over 1,000 reports, or a `new_program` that already has over 300.
- **low:** `scope_added` on a program with under 300 reports (or unknown); a `new_program` with 0
  reports; a `new_program` with no report count but launched in the last 14 days.
- **medium:** everything else, including a `new_program` that arrives with 1-300 reports and fresh
  scope on a heavily reported program (new asset, crowded neighbourhood).

## angle

The concrete first move, in 15 words or fewer: which asset or surface to touch first and what to look
for. Base it on the actual assets and on the profile.

If `dup_risk` is **high**, the angle must be a depth vector (mobile app to backend, business logic,
access control on a non-obvious object, an API operation the web UI doesn't use) and must start with
`DEPTH: `. Never propose commodity bugs as the angle when `dup_risk` is high.

## reasons

Two or three short strings, 20 words or fewer each, naming the signals that moved the score most
(for example "fresh API asset on a paying program", "1,400 reports: heavy duplicate risk").

---

## Output

Return one verdict per alert, with the alert's `id` copied unchanged:

```json
{"verdicts": [{"id": "ywh:example", "verdict": "GO", "score": 78, "dup_risk": "low",
  "angle": "Enumerate order IDs on the new API; test cross-account access",
  "reasons": ["fresh API asset on a paying program", "few reports"]}]}
```

`verdict` is GO, FYI or SKIP. `score` is an integer from 0 to 100. `dup_risk` is low, medium or high.
The workflow enforces this schema, so put all reasoning into `reasons` and `angle`, never extra
fields.
