# Security policy

## Reporting a vulnerability in bountyproof

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/jorge-asenjo/bountyproof/security/advisories/new)
rather than a public issue.

Especially welcome:
- ways to get a network request past the scope guard (`hooks/scope-guard.mjs`) that it should catch,
- secrets that end up unredacted in `notes/egress-log.jsonl`,
- anything in the templates or prompts that would push an agent outside a program's rules.

Please include the `scope.json` and the exact tool input (command or URL) that reproduces it. I aim
to answer within a week.

## Scope-guard bypasses and known limits

The guard reads the command text Claude Code is about to run. It does not see what a script does
at runtime or requests made from inside a browser page. Those limits are documented and the
workspace rules forbid relying on them; reports that show a practical bypass of what the guard
*claims* to cover are still very welcome.
