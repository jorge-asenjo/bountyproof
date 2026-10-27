# Phase 0: Program Setup

Mandatory before any hunting.

> **Selection gate (before you invest).** Run `reference/program-selection-scorecard.md`. If the
> program hits a KILL criterion (VDP when you need income, no obtainable authenticated account, your
> vector is already out of scope or a known issue), stop here. In practice the bottleneck is rarely
> technique: it is picking saturated, unpaid or unreachable targets. Record the scorecard result in
> `STRATEGY.md`.

> **Mode check (set this first).** Is the target SOURCE-AVAILABLE (repos to clone + a local Docker
> lab) or BLACK-BOX / LIVE (no source; test the live in-scope hosts with the browser + curl)? The
> workspace was created with `--mode whitebox|blackbox` and its `CLAUDE.md` reflects that. Steps 5-6
> are **white-box only**; black-box replaces them with steps 5b-6b.

## Tasks

0. **Read `notes/hunter-profile.md`** if it exists (`bountyproof onboard` writes it). It lists the
   hunter's platform username, devices, tools, parallel capacity and limits. Plan only with what it
   lists: no mobile work without a device or decompiler marked available, no white-box lab if Docker
   is missing, no more parallel browser sessions or labs than it allows. If the program needs
   something the profile rules out, say so in the selection gate.

1. **Ingest the program page.** Platform program pages sit behind a login and a JS app, so a plain
   web fetch usually fails. Use one of:
   - **Browser (preferred):** open the program page with the Playwright MCP browser (log in once
     when it opens) and read the scope, out-of-scope list, reward grid and rules from the page.
   - **Paste:** ask the user to paste the full program page into `notes/program-raw.md`, then parse it.

   Extract:
   - Scope (hosts, apps, repos, versions)
   - **Out of scope + known issues + "won't fix" items**, copied explicitly. They decide what not to
     even attempt: a well-evidenced report on a documented-as-accepted vector is closed as out of scope.
   - Reward grid (and whether it is a VDP / points-only program)
   - Report format requirements
   - Rules and constraints (required UA tag or headers, rate limits, scanner policy)
   - **AI and third-party tool clauses** (step 2b)

2. **Copy all program rules verbatim** into `notes/program-rules.md`.

2b. **AI and data-handling check.** Search the program page, the platform's researcher terms and any
    NDA for: AI, LLM, "automated", "third-party tools/services", "share data", "disclosure". Record
    one of these in `STRATEGY.md`:
    - `AI: allowed`: nothing restricts it.
    - `AI: disclosure required`: Phase 4a adds one honest line on how AI assisted, and it stays in v2.
    - `AI: restricted`: no third-party worker models (Gemini/Codex) on target data. Use Claude
      subagents only, and only if the clause allows that.
    Remember that every model you delegate to receives whatever you pass it.

2c. **High-consequence target?** If the target is payments, banking, transfer rails, healthcare,
    energy or other critical infrastructure, write `HIGH-CONSEQUENCE` in `STRATEGY.md`. Same
    autonomy on your own test accounts and objects; never touch other users' money or data;
    real-money actions in production stay with the human. If the model declines a step, don't retry
    or reword it: skip it and note it in the case file.

3. **Read the threat model / security docs** (specs, whitepapers, infrastructure docs) and summarize
   them in `notes/threat-model.md`:
   - Parties and trust levels
   - Adversary capabilities
   - Security properties protected
   - What is out of scope

   **Then build a TRUSTED vs UNTRUSTED component map.** List every component and classify it:
   ```
   ## Component trust map
   - Public API: UNTRUSTED (attack target)
   - Web client: UNTRUSTED (attack target)
   - Print/offline component: TRUSTED (physical access only, out of scope)
   - Admin console: TRUSTED (authorized insiders only)
   ```
   Hunt only in UNTRUSTED components. Bugs in TRUSTED components are rejected automatically.

4. **Fill `STRATEGY.md`**: scope, rewards, threat-model summary, tech stack, high-value bug classes.

5. **(White-box) Clone the repositories** into `source/`.

6. **(White-box) Configure the Docker lab** in `docker/` with the right images and init scripts.

5b. **(Black-box) Set the program's required UA tag / headers** in `.mcp.json` (browser) and note
    them for curl. Record any feature-flag cookies or headers needed to reach flows.

6b. **(Black-box) Prepare accounts.** The human registers the test accounts, following the program's
    policy (email alias rules). Authorization testing needs TWO accounts (A and B) plus an anonymous
    session.

6c. **(Both modes) Fill `notes/scope.json`**, the machine-readable scope that the `scope-guard` hook
    enforces on every network command and browser navigation (out-of-scope host → blocked, missing
    UA tag → blocked, unknown host → blocked, optional confirmation for state-changing requests;
    everything logged to `notes/egress-log.jsonl`).
    - `inScope`: exact hosts and `*.domain` wildcards (list the apex separately), IPv4 CIDRs.
    - `outOfScope`: the OOS list + registration-only hosts + sister brands + unlisted staging hosts.
    - `denyUnlisted`: when the program says "any `*.acme.com` host not listed is out of scope", put
      `acme.com` and `*.acme.com` here.
    - `uaTag` / `requiredHeaders`: exactly what the program requires on every request.
    - `hunterInfra`: your own out-of-band endpoints. `allowHosts`: non-target hosts you need.
    - White-box: `inScope` = the lab hosts; the program's production domains go in `outOfScope`.

    Sanity-check it without sending anything: `bountyproof scope check "<in-scope URL>"` must allow,
    and `bountyproof scope check "<OOS URL>"` must deny.

    **Black-box workspaces start with `requireConfirm: true`.** The hook blocks all live in-scope
    testing until the human reviews the scope against the program page and runs
    `bountyproof scope confirm` in their own terminal (the hook won't let you run it). Any later
    edit to the scope re-blocks it. End Phase 0 by showing the scope and asking for that
    confirmation.

7. **Output a summary** and confirm readiness for Phase 1.

## Important
- If there is a formal security spec or threat model, read it before the code or the live app.
- Do not skip steps.
- Use the form guide for this platform: `reference/form-reference.md`.
