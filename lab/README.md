# Demo lab

Run the whole bountyproof pipeline against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
an intentionally vulnerable app, on your own machine. No bounty account, no third-party servers.

## Steps

```bash
# 1. Start the target (bound to 127.0.0.1 only)
docker compose -f lab/docker-compose.yml up -d

# 2. Create a workspace and drop in the lab scope
bountyproof new "Juice Shop Lab" --mode blackbox --dir ./engagements
cp lab/scope.json engagements/juice-shop-lab-hackerone/notes/scope.json

# 3. Check the guard: the lab is allowed, the internet is not
cd engagements/juice-shop-lab-hackerone
bountyproof scope check http://localhost:3000/rest/products/search?q=apple   # ALLOW
bountyproof scope check https://example.com/                                # DENY

# 4. Hunt
claude
```

In Claude Code, run `/bountyproof:setup` and paste [`program-rules.md`](program-rules.md) as the program
page, then `/bountyproof:recon`, `/bountyproof:discover`, `/bountyproof:validate` and
`/bountyproof:judge`. When you're done, `bountyproof funnel` shows how many hypotheses survived each gate.

Stop the lab with `docker compose -f lab/docker-compose.yml down`.

## Notes
- `engagements/` is gitignored in this repo, so lab workspaces never get committed by accident.
- Juice Shop's challenge list is a convenient ground truth for measuring the pipeline (see the
  Evals item in the roadmap).
- Never expose Juice Shop beyond `127.0.0.1`: it is vulnerable on purpose.
