# Phase 1: Reconnaissance

Map the architecture and the attack surface → `notes/attack-surface.md`.

> **Mode check.** White-box → map the cloned code as below. Black-box → there is no source: drive
> the target in the browser (Playwright MCP) as an authenticated user and record the real surface
> (endpoints, parameters, object IDs, auth tokens' shape) from the captured network requests into
> `notes/case-file.md`. See `reference/browser-playbook.md`. The output format below applies to
> both modes.

> **Wildcard scope (black-box)?** For a `*.target.com` scope, widen the map passively before
> touching anything: certificate-transparency subdomain sources (`crt.sh` is allowed by default)
> and a resolver/prober such as `httpx` to see what is alive. Both carry the UA tag and pass
> through the scope-guard. Do **not** reach for mass vulnerability scanners here: most programs
> forbid them, and their output is reachability, not impact. Map breadth passively; prove impact by
> hand in Phases 2-3.

## Small target (<50k LOC, or a handful of live surfaces)
Do it directly, or with a single read-only subagent. No fan-out.

## Large target (>50k LOC, or many live surfaces): fan out

Spawn 2-3 parallel read-only subagents in ONE message so they run concurrently, each with a
distinct area:

- "Map all HTTP endpoints / API routes / GraphQL operations, their methods and required permissions."
- "Map the auth and authz model: how users and sessions are created, roles, tenant/ownership model."
- "Map trust boundaries: where unauthenticated and authenticated zones meet, where user input enters
  server-side processing, external integrations (fetchers, webhooks, file handling, crypto)."

Then you (the orchestrator) compile their returns into `notes/attack-surface.md`. For very large
source trees you can also delegate a broad read-only pass to Gemini (see
`reference/agent-architecture.md`).

### Output format for attack-surface.md
For each area:
- Area name
- Entry points (URLs, methods, operations)
- Required permissions
- Key source files (white-box) or observed requests (black-box)
- Plausible bug classes
- Priority (HIGH / MEDIUM / LOW), based on alignment with the threat model

### When done
Proceed to Phase 2.
