# Contributing

Thanks for helping. bountyproof is a harness, so most contributions are prompts, reference docs,
guard rules or CLI code.

## Ground rules
- Every change keeps the core contract: discovery never confirms itself, the judge gates every
  report, the scope guard stays fail-open and deterministic, and the agent never submits.
- No real program names, report IDs, targets or credentials in examples. Use `example.com`,
  `acme.example` and placeholders.
- Methodology over payloads. Reference docs describe evidence standards and process; this repo
  doesn't collect exploit payloads.

## Development

```bash
git clone https://github.com/jorge-asenjo/bountyproof && cd bountyproof
uv sync --group dev            # or: python -m pip install -e . pytest ruff
uv run pytest                  # CLI tests
node --test tests/*.test.mjs   # scope-guard battery
uv run ruff check . && uv run ruff format --check .
claude plugin validate .       # plugin manifest, skills, agents
```

Try the plugin from your checkout without installing it: `claude --plugin-dir .`

## Changing the scope guard
- Add a case to `tests/scope-guard.test.mjs` for every behavior you change or fix.
- Keep it fail-open (an internal error must exit 0 with no output).
- If you touch the scope hash, keep `src/bountyproof/scope.py` in sync; the parity test will tell you.

## Layout
| Path | What it is |
|---|---|
| `.claude-plugin/` | plugin and marketplace manifests |
| `skills/`, `agents/`, `hooks/` | the Claude Code plugin |
| `prompts/` | phase instructions (copied into each workspace) |
| `reference/` | methodology docs (copied into each workspace) |
| `template/` | the workspace scaffold |
| `src/bountyproof/` | the CLI |
| `radar/` | program watcher (GitHub Actions templates) |
| `lab/` | local demo target |
