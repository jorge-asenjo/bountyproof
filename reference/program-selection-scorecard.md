# Program Selection Scorecard (gate BEFORE Phase 0)

> In practice, the bottleneck is rarely technique. It's picking the wrong program or the wrong
> vector. Most engagements that go nowhere end as duplicate / informative / out of scope / an unpaid
> VDP, or get abandoned after a lot of recon. Run this gate BEFORE creating the workspace
> (`prompts/00-setup-program.md`) and before spending hours on a target.

## How to use it
Score the program. **If anything in section A is a KILL, don't take it**, however interesting the
target looks. If it passes A, use B to rank candidates against each other. Record the result in
`STRATEGY.md`.

## A. KILL criteria (any one = drop it, unless you note an explicit exception)

- [ ] **Is it a VDP (no money)?** → KILL, unless your explicit goal right now is reputation or
      platform points.
- [ ] **Do you need an authenticated account you CAN'T get** (corporate/.gov email, invitation only,
      KYC, mandatory real payment)? → KILL, or downgrade to "only if the goal is the unauthenticated
      surface". Most high-value bug classes (IDOR/BOLA, business logic, tenant isolation) live
      behind login.
- [ ] **Is the vector you plan to attack listed as out of scope / known issue / "by design"?** → KILL
      that vector. (A program closed two well-evidenced reports as out of scope because tenant
      isolation was the reverse proxy's job. That was predictable from reading the scope.)
- [ ] **Does the program have an AI clause?** → Respect it: disclose AI assistance when the program
      requires it, and if AI use is restricted, don't send target data to third-party models. If the
      clause rules out the workflow you would actually use, KILL.

## B. Prioritization score (higher = better expected return)

Add up the points. Compare candidates and work the one with the highest score.

**Money and maturity**
- Pays bounties (not a VDP): **+3**
- High reward grid (critical ≥ €3k or equivalent): **+2**
- New program (< 3 months) or **recently expanded scope**: **+3**  ← fresh code = fewer duplicates
- Pays fast / responsive triage (track record): **+1**

**Competition (avoiding duplicates)**
- Few reports in the last 90 days relative to the size of the scope: **+2**
- Heavy report volume on a mature target (e.g. a mature target with ~600 reports in 90 days): **−3**
- Very high reports-to-resolved ratio (lots of noise, worn-out triage): **−1**

**Surface you can actually test**
- Source available (open source / public repos), fully or partly: **+3**  ← file:line evidence and
  a PoC of the code path
- Self-service authenticated account (open registration): **+2**
- You can create 2 accounts for IDOR/BOLA plus a guest: **+1**
- Wide, heterogeneous surface (several subdomains, APIs, apps): **+1**

**Fit**
- Surfaces or bug classes where you have a demonstrated edge, meaning accepted findings rather than
  interest (e.g. OAuth/OIDC, GraphQL, business logic, white-box code review, mobile static
  analysis): **+2**

## C. Rules of thumb

1. **Fresh scope beats famous scope.** Being first on newly added code beats arriving late to a
   saturated target. Watching for new programs and scope changes pays off more than anything else.
2. **No account, no impactful bug.** If you can't authenticate, either get access before investing
   in recon, or assume the ceiling is "out-of-scope info disclosure" and probably pass.
3. **Read the out-of-scope / known-issues section BEFORE validating anything.** Copy it into
   `notes/threat-model.md`. If your idea is already on that list, change ideas.
4. **White-box pays off more than black-box** with this harness (file:line rigor plus a PoC of the
   code path). When in doubt, prefer source-available targets.
5. **A VDP only when the explicit goal is reputation.** Don't mix the two: don't put two days of
   work into a VDP hoping for money.
6. **One good program worked in depth beats five workspaces** created and abandoned at Phase 0.
   Abandoned scaffolds are just noise.
