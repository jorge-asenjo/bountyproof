"""Generate the evidence-judge eval cases. Run from the repo root: python evals/generate.py"""

from pathlib import Path

ROOT = Path("evals")

RULES = """# Program Rules: Acme Shop (fictional eval program)

## In scope
- app.example.com (customer web app)
- api.example.com (public API)

## Out of scope
- status.example.com
- legacy.example.com (legacy merchant portal). Tenant isolation on the legacy portal is enforced by the
  reverse proxy and is considered out of scope.
- Third-party payment widget

## Not eligible
- Missing security headers, clickjacking, self-XSS, rate limiting
- Information that the user's role can already see in the product UI

## Rules
- Use test accounts you create yourself. No DoS.
"""

THREAT = """# Threat Model

## Component trust map
- Customer web app (app.example.com): UNTRUSTED (attack target)
- Public API (api.example.com): UNTRUSTED (attack target)
- Admin console: TRUSTED (Acme staff only, behind SSO)
- Legacy merchant portal (legacy.example.com): out of scope
"""

SCOPE = """{
  "enforce": true,
  "inScope": ["app.example.com", "api.example.com"],
  "outOfScope": ["status.example.com", "legacy.example.com"],
  "denyUnlisted": ["example.com", "*.example.com"],
  "uaTag": "BugBounty-evals"
}
"""

TABLE_HEAD = """| ID | Class | Shard / artifact | Trust boundary | Confidence | Status |
|----|-------|------------------|----------------|------------|--------|
"""
LOG_HEAD = """| ID | Test run | Negative control | Result | Artifact ref |
|----|----------|------------------|--------|--------------|
"""


def case_file(facts, row, dossier, log):
    return (
        "# Case File\n\n## 1. Facts\n"
        + facts
        + "\n\n## 2. Hypotheses\n"
        + TABLE_HEAD
        + row
        + "\n\n## 3. Evidence dossiers\n"
        + dossier
        + "\n\n## 4. Validation log\n"
        + LOG_HEAD
        + log
        + "\n"
    )


CASES = {
    "judge-rejects-reachability-only": dict(
        expect="reject",
        tags=["judge", "slop"],
        desc="An authorization finding whose only evidence is a 200 status with no foreign data.",
        file=case_file(
            "- Orders are fetched with GET /api/orders/{id}. Order IDs are sequential integers.",
            "| H-001 | authz | orders API | account | high | confirmed |",
            """### H-001 - Cross-account access on the order endpoint
- Affected asset / trust boundary: api.example.com, between customer accounts
- Preconditions: attacker has a customer account (account A)
- Expected observation if vulnerable: account A receives account B's order data
- Best benign alternative explanation: the endpoint answers 200 for any ID but only returns data the caller owns
- Validation result + artifacts:
  - Negative control: A requests /api/orders/1001 (A's own order): 200, body contains A's order details
  - Test: A requests /api/orders/1002 (B's order): 200, body is {"status":"ok"}
- Status: confirmed""",
            "| H-001 | A requests B's order 1002 | A requests own order | 200 OK | poc/h001.txt (status line only) |",
        ),
    ),
    "judge-rejects-already-obtainable": dict(
        expect="reject",
        tags=["judge", "slop"],
        desc="A disclosure of data the same role already sees in the product UI.",
        file=case_file(
            "- The Team page in the web app lists every teammate's name and email to all members of the team.",
            "| H-001 | info disclosure | team API | team member | medium | confirmed |",
            """### H-001 - Teammate emails exposed by /api/team/members
- Affected asset / trust boundary: api.example.com, member role
- Preconditions: attacker is a regular member of the team
- Expected observation if vulnerable: a member can read teammates' emails
- Best benign alternative explanation: members are meant to see teammates' emails
- Validation result + artifacts:
  - Member account C requests /api/team/members: 200, JSON with names and emails of the 4 teammates
- Status: confirmed""",
            "| H-001 | member lists team | anonymous gets 401 | emails returned | poc/h001.json |",
        ),
    ),
    "judge-rejects-out-of-scope-by-design": dict(
        expect="reject",
        tags=["judge", "scope"],
        desc="A well-evidenced cross-tenant read on an asset the program excludes by design.",
        file=case_file(
            "- Merchants manage their stores in the legacy portal at legacy.example.com.",
            "| H-001 | authz | legacy portal | tenant | high | confirmed |",
            """### H-001 - Cross-tenant store read in the legacy merchant portal
- Affected asset / trust boundary: legacy.example.com, between merchant tenants
- Preconditions: attacker owns a merchant tenant (tenant A)
- Expected observation if vulnerable: tenant A reads tenant B's store settings
- Best benign alternative explanation: none found
- Validation result + artifacts:
  - Negative control: tenant A reads its own settings: 200
  - Test: tenant A requests tenant B's settings: 200 with tenant B's settings (both are test tenants)
- Status: confirmed""",
            "| H-001 | A reads B's settings | A reads own settings | B's data returned | poc/h001.txt |",
        ),
    ),
    "judge-rejects-insider-precondition": dict(
        expect="reject",
        tags=["judge", "threat-model"],
        desc="A stored injection that requires staff access to a trusted admin console.",
        file=case_file(
            "- Order notes can be edited in the admin console, which only Acme staff can reach through SSO.",
            "| H-001 | xss | admin console | staff | medium | confirmed |",
            """### H-001 - Stored script injection in admin order notes
- Affected asset / trust boundary: admin console
- Preconditions: attacker is an Acme staff member with the admin role
- Expected observation if vulnerable: markup in a note renders for other staff viewing the order
- Best benign alternative explanation: none
- Validation result + artifacts:
  - Using a staff test account, a note containing an HTML test string rendered unescaped
- Status: confirmed""",
            "| H-001 | staff note with HTML | plain-text note | rendered unescaped | poc/h001.png |",
        ),
    ),
    "judge-needs-validation-missing-artifact": dict(
        expect="needs_validation",
        tags=["judge", "evidence"],
        desc="A plausible race condition with no captured discriminating artifact.",
        file=case_file(
            "- Single-use coupons are redeemed with POST /api/coupons/redeem.",
            "| H-001 | logic | coupons | account | medium | confirmed |",
            """### H-001 - Single-use coupon applied twice with parallel requests
- Affected asset / trust boundary: api.example.com, coupon redemption
- Preconditions: attacker has one single-use coupon on their own account
- Expected observation if vulnerable: two orders get the coupon discount
- Best benign alternative explanation: the second redemption is rejected, or only one order keeps the discount
- Validation result + artifacts:
  - Sent 20 parallel redeem requests from account A. It looked like the coupon was applied twice.
  - No responses or order totals were saved.
- Status: confirmed""",
            "| H-001 | 20 parallel redeems | single redeem | looked like 2 applied | (none) |",
        ),
    ),
    "judge-passes-proven-finding": dict(
        expect="pass",
        tags=["judge", "control"],
        desc="A cross-account read proven between two test accounts with controls. Should PASS.",
        file=case_file(
            "- Orders are fetched with GET /api/orders/{id}. Order IDs are sequential integers and appear on\n"
            "  order confirmation pages.",
            "| H-001 | authz | orders API | account | high | confirmed |",
            """### H-001 - Cross-account order read on GET /api/orders/{id}
- Affected asset / trust boundary: api.example.com (UNTRUSTED), between customer accounts
- Preconditions: attacker has any customer account; no other privilege
- Attacker control of input: the order ID in the path
- Attacker control of resource/object: order IDs are sequential, so other customers' IDs are predictable
- Expected observation if vulnerable: account A receives account B's order details
- Best benign alternative explanation: the API returns only the caller's own orders, or an error
- Validation result + artifacts (both accounts are the researcher's own test accounts):
  - Negative control 1: A requests /api/orders/1001 (A's order): 200, A's name and address
  - Negative control 2: anonymous requests /api/orders/1002: 401
  - Negative control 3: B requests /api/orders/1002 (B's order): 200, "Test User B" and B's test address
  - Discriminating test: A's session requests /api/orders/1002: 200, body contains "Test User B" and
    B's test address. Reproduced twice. Requests and responses saved in poc/h001-*.txt
- Status: confirmed""",
            "| H-001 | A reads B's order 1002 | A own order; anon 401; B own order "
            "| B's data returned to A | poc/h001-a-reads-b.txt |",
        ),
    ),
}

PROMPT = """---
description: {desc}
max_turns: 20
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Agent]
---

Before I write a report, judge finding H-001 in this engagement workspace. The files are in the current
directory: notes/case-file.md, notes/program-rules.md and notes/threat-model.md. Use the bountyproof judge
agent if you have it. Finish with exactly one line in the form `JUDGE H-001: PASS`,
`JUDGE H-001: NEEDS_VALIDATION` or `JUDGE H-001: DISCARD`.
"""

VERDICTS = {
    "pass": r"JUDGE H-001:\s*`?PASS",
    "needs_validation": r"JUDGE H-001:\s*`?NEEDS_VALIDATION",
    "reject": r"JUDGE H-001:\s*`?(NEEDS_VALIDATION|DISCARD)",
}


def heredoc(path, text):
    return f"mkdir -p \"$(dirname '{path}')\"\ncat > '{path}' <<'BP_EOF'\n{text.rstrip()}\nBP_EOF\n"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


for name, c in CASES.items():
    d = ROOT / name
    script = "#!/usr/bin/env bash\n# Seeds the fictional engagement workspace for this case.\nset -euo pipefail\n"
    for rel, text in (
        ("notes/program-rules.md", RULES),
        ("notes/threat-model.md", THREAT),
        ("notes/scope.json", SCOPE),
        ("notes/case-file.md", c["file"]),
    ):
        script += heredoc(rel, text)
    write(d / "scaffold.sh", script)
    write(
        d / "case.yaml",
        f'schema_version: "1.1"\nname: {name}\ntags: [{", ".join(c["tags"])}]\n'
        f'expected_outcome: "{c["expect"]}"\ncontext:\n  scaffold_script: scaffold.sh\n',
    )
    write(d / "prompt.md", PROMPT.format(desc=c["desc"]))
    write(
        d / "graders" / "verdict.md",
        f"---\ntype: regex\ntarget: last_message\npattern: '{VERDICTS[c['expect']]}'\nweight: 3\n---\n",
    )
    if c["expect"] != "pass":
        write(
            d / "graders" / "no-pass.md",
            f"---\ntype: regex\ntarget: last_message\npattern: '{VERDICTS['pass']}'\nmatch: not_contains\n---\n",
        )
    write(
        d / "graders" / "used-judge.md",
        "---\ntype: tool_used\ntool: Agent\ninput_match: 'bountyproof:judge'\narm: with-only\n---\n",
    )

print("\n".join(sorted(str(p) for p in ROOT.rglob("*") if p.is_file())))
