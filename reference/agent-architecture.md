# Agent Architecture for Bug Bounty (multi-model harness)

> Derived from public research and write-ups on agentic vulnerability discovery (Naptime/Big Sleep,
> XBOW, PentestGPT, Codex Security, Mozilla×Anthropic, CORRECT/JITVul, plus Anthropic's own
> agent-engineering guidance).
> **Core thesis: capability comes from the *harness*, not from a magic prompt.** The biggest
> measurable gains come from context selection, worker specialization, separating discovery
> from validation, a disciplined memory model, and hard evidence criteria — NOT from longer or
> "cleverer" prompts. Optimize the architecture, not the wording.

This is the canonical methodology doc. Phases 02/03 implement it. Read it once, then follow the
phase prompts.

---

## 1. The control loop: planner → divergent workers → convergent validator → judge

```
[Scope + program rules + threat model]
            │
            ▼
   [Orchestrator]  ← plans, shards work, owns the case file, is the evidence judge
            │
   ┌────────┼────────┐
   ▼        ▼        ▼
[worker]  [worker]  [worker]   ← DIVERGENT discovery, read-only, independent hypotheses
   │        │        │
   └────────┼────────┘
            ▼
   [Case File]  facts / hypotheses / evidence / validation   ← canonical shared memory
            │
            ▼
   [Dynamic Validator]   ← SEPARATE role; isolated lab (white-box) or live in-scope target
            │              (black-box); negative controls first
            ▼
   [Evidence Judge]  ← the orchestrator again; nothing is "confirmed" without a complete dossier
            │
            ▼
   [Report only: confirmed findings OR candidates with a falsifiable reproducer]
```

Four rules this encodes (each backed by the sources):
1. **Navigate the repo with tools, don't dump it into context.** Selective retrieval beats raw context.
2. **Sample independent hypotheses in parallel** instead of one deep reasoning tree (avoids drift).
3. **Validation is a separate role from discovery.** The agent that finds a bug must NOT be the one that confirms it — same evidence + same framing = reinforced hallucination.
4. **Memory is a structured case file, not a long transcript.** Workers read/write canonical summaries in `notes/case-file.md`.

---

## 2. Worker specialization (who does what, and why)

| Role | Backend | Why |
|------|---------|-----|
| **Orchestrator / Judge** | The orchestrator model (a large-context Claude model; this session, max effort) | Long-horizon agentic planning + evidence adjudication. |
| **Variant hunter / broad read-only explorer** | Gemini (`--approval-mode plan`) | Big read-only shards, diff-seeded variant analysis (the public Big Sleep flow used Gemini). |
| **Authz / logic explorer** | Gemini or a Claude sub-agent | Multi-tenant object/ownership mapping, server-side check tracing. |
| **Threat-model + validation + patch** | Codex (`codex exec`) | Codex Security is built around repo-specific threat models, sandbox validation, and patch proposals. |

**Shard by ARTIFACT and TRUST BOUNDARY, not by CWE.** Sharding by CWE produces overlap and gaps.
Good shards for the bug classes we target:
- Actor/tenant resolution from request → storage (BOLA/IDOR).
- Caches, queues, async jobs and side effects that bypass authz.
- Fetchers, webhooks, proxies, renderers, parsers with outbound/remote output (SSRF/RCE).
- Non-idempotent state-change operations susceptible to races.
- Recent diffs touching checks, normalization, serialization, or ownership (variant analysis).

**When NOT to go multi-model:** small target, tightly-scoped bug class, and no validation lab.
Coordination overhead can exceed the benefit; a bad wrapper just amplifies noise (the o3 case).

---

## 3. Delegating to Codex and Gemini (CLI cookbook)

Both CLIs must be installed and callable from the Bash/PowerShell tool. The workspace ships
PowerShell helper scripts in `tools/scripts/` (`ask-codex.ps1`, `ask-gemini.ps1`); the equivalent
direct CLI calls below work on any OS (macOS, Linux, Windows).

**Gemini — read-only static auditor (safe, cannot edit):**
```bash
gemini -p "<auditor prompt + shard>" --approval-mode plan --include-directories source
```
- `--approval-mode plan` = read-only mode. Always use it for discovery workers.
- `-m <model>` picks the model; `-o json` gives parseable output when you want the orchestrator to
  ingest results programmatically.

**Codex — non-interactive worker (threat model / validation reasoning):**
```bash
codex exec "<prompt>"
# read-only sandbox for discovery:
codex exec -c 'sandbox_permissions=["disk-full-read-access"]' "<prompt>"
# built-in code review against current repo:
codex exec review
```
- `-m <model>` picks the model.
- Long prompts: pipe via stdin → `cat shard.txt | codex exec -` (on Windows PowerShell:
  `Get-Content shard.txt | codex exec -`).

**Hard rules for delegation:**
- Discovery workers run **read-only** (`--approval-mode plan` / read-only sandbox). No writes, no network attacks.
- Give each worker ONE shard + the threat model + the evidence format. Never the whole repo.
- Workers return **hypotheses with dossiers**, never "confirmed" findings. Confirmation is the validator+judge's job.
- The orchestrator ingests worker output into the case file and decides what gets promoted.

---

## 4. The evidence gate (what makes a finding real)

A finding does NOT exist until it has a complete dossier. Every hypothesis must carry:

1. Affected asset + trust boundary
2. Code path / handler sequence (source → transforms → checks → sink/action)
3. Preconditions
4. Attacker control of input
5. Attacker control of the resource/object
6. Expected observation if vulnerable
7. **Best benign alternative explanation** (mandatory — kills authz/SSRF/injection false positives)
8. **Minimal falsifiable test** that distinguishes vulnerable from benign
9. Validation result + captured artifacts (request/response, logs, state diff)

Status ladder: `candidate` → (validator) → `confirmed` / `rejected` / `inconclusive`.
- No lab yet? The ceiling is **`candidate with falsifiable reproducer`**, never `confirmed`.
- Critic/judge sees DIFFERENT framing than the discoverer, and demands: necessary exploitation
  conditions, the benign alternative, and the discriminating test. Missing any → don't promote.
- Class-specific minimum proof and overclaim traps live in `reference/vuln-class-gotchas.md`.

---

## 5. Anti-patterns that turn agents into garbage-report generators

- One agent that discovers, validates AND writes → self-confirms its own hallucination.
- "Smell" treated as finding: scary function name / sink / suspicious check without reachability + input/object control.
- Dumping raw context into one long conversation instead of selective retrieval → drift + lower quality.
- No mandatory benign alternative + discriminating test → authz/SSRF/injection false positives.
- State living only in the chat transcript → workers collide, orchestrator forgets decisions.
- Sharding by CWE in the abstract → overlap and gaps.
- Compensating for a weak harness with longer prompts → evidence says architecture > prose.
- Asking for PoCs too early → build evidence, validate, THEN write the minimal reproducer.

---

## 6. Local tooling & MCP recommendations

Baseline: node, python, docker (white-box lab), ripgrep, git, gh, and the `claude`, `codex` and
`gemini` CLIs.

**Worth installing (high value, low effort):**
- **semgrep** (`pip install semgrep`) — fast static-analysis seeding for workers. Run `semgrep --config auto source/` to generate candidate sinks the orchestrator can triage. NOT a finding source by itself — feed results through the evidence gate.
- **jq** (`brew install jq` / `apt install jq` / `winget install jqlang.jq`) — parse `gemini -o json` / `gh api` output in scripts.
- **CodeQL CLI** (optional, heavier) — interprocedural taint analysis for serious source→sink reachability on C/Java/JS/Python targets. Best ROI on large codebases; pairs well with the "variant analysis" shard.

**MCP servers worth wiring into Claude Code / Codex / Gemini (only if a target needs them):**
- **Playwright MCP — PRE-WIRED in `template/.mcp.json`.** This is the big autonomy win for black-box
  web targets: the Claude session DRIVES a real Chrome (navigate, click, fill, read network + console,
  screenshot) so the human only does login / captcha / 2FA. Setup per engagement:
  1. The template ships `.mcp.json` with a persistent profile (`./tools/browser/profile`) and headed
     real Chrome. Edit it: append the program's required UA tag, if any (e.g. `BugBounty/<handle>`),
     and add OOS hosts to `--blocked-origins`. **Restart Claude Code** to load the server.
  2. First browser tool call opens Chrome with the persistent profile → the **user logs in once**
     (handles captcha + 2FA). The profile persists, so every later run reuses the session.
  3. Claude then drives all flows itself (walk multi-step flows, submit forms, replay requests)
     and reads responses via the `browser_network_requests` tool. No more "capture it in Chrome for me".
  - Captcha and SMS 2FA still need the human — that's the *only* manual step. Keep ≤ rate limit;
    headed real-Chrome + persistent profile is the most Cloudflare/bot-mgmt-friendly setup.
  - `tools/browser/profile/` holds session cookies → keep it **gitignored** (it's secrets).
  - Details: `reference/browser-playbook.md`.
- **Burp Suite MCP** (community) — drive an intercepting proxy for the dynamic validator (CAI uses Burp via MCP).
- **Local filesystem / git MCP** — cleaner repo navigation for sub-agents than raw shell.
- Keep MCP minimal: every server is attack surface + context cost. Add per-engagement, not globally.

**Repos worth studying (structure, not copy-paste):**
- `Piebald-AI/claude-code-system-prompts` and `x1xhlol/system-prompts-and-models-of-ai-tools` — system-prompt *structure* patterns.
- Google Project Zero "Naptime" write-up + Project Naptime/Big Sleep posts — the reference harness.
- `protectai/vulnhuntr` — zero-shot source→sink call-chain analysis for Python targets.

**Tooling repos — curated with a critical lens (most "N-agents" repos are prompt piles; arch > prose):**
- **Burp MCP** — `swgee/BurpMCP` or PortSwigger's official MCP. The real complement to Playwright MCP:
  lets the session tamper requests (Repeater/Intruder/site-map) for the dynamic validator. Needs Burp
  running. Wire only when request-tampering is needed beyond curl replay. Highest-signal add.
- **`shuvonsec/claude-bug-bounty`** — worth MINING for its *auth-aware hunting* pattern (authenticated
  session carried into httpx/katana/ffuf/nuclei/dalfox) and persistent hunt memory. Its "20 vuln
  classes / autonomous" breadth is exactly the noise our evidence gate exists to filter — don't adopt wholesale.
- **Recon toolchain** (`projectdiscovery/nuclei`, `httpx`, `katana`, `ffuf`, `dalfox`) — solid, real.
  Best for source-code / broad-scope programs. On strict live targets (rate-limited, gentle-tooling-only,
  high-duplicate) generic scanner output is mostly dupes and risks rule violations — use sparingly, `-rl` always.
- **Skip for strict live targets:** `0x4m4/hexstrike-ai` (150+ tools autonomous — heavy, OOS/rate risk),
  `gokulapap/bugbounty-mcp-server` (nmap/shodan — infra recon, OOS risk on SaaS), `pikpikcu/airecon`
  (a local Ollama agent is weaker than the hosted Claude/Codex/Gemini models used here; only its payload
  DB is interesting), `H-mmer/pentest-agents` & `matty69v/Bug-Bounty-Agents` (prompt-pile personas —
  mine for vuln-class checklists, not as architecture).
