---
description: "Create a new bountyproof engagement workspace (rules, phase prompts, case file, scope guard) for a bug bounty program."
argument-hint: "<program-name> [--platform ywh|intigriti|hackerone] [--mode blackbox|whitebox]"
disable-model-invocation: true
---

Create a new engagement workspace with the bountyproof CLI. It has no dependencies beyond Python 3.10+.

1. Build the command from the arguments (`$ARGUMENTS`). Defaults: `--platform hackerone`,
   `--mode blackbox`. If the user gave no program name, ask for one.
2. Run the first form that works:
   - `bountyproof new $ARGUMENTS` (when the CLI is installed, e.g. with `uv tool install`)
   - `python "${CLAUDE_PLUGIN_ROOT}/scripts/bountyproof.py" new $ARGUMENTS`
     (use `python3` if `python` isn't found)
3. Report the workspace path the CLI printed, then tell the user the next steps:
   - open a new Claude Code session inside that folder (the workspace has its own `CLAUDE.md`);
   - black-box: set the program's UA tag in `.mcp.json` first if the program requires one;
   - run `/bountyproof:setup <program URL>`.

Don't start hunting from this session: the engagement rules load from the workspace's `CLAUDE.md`.
