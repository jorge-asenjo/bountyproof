# Responsible use

bountyproof drives an AI agent that can send network requests. Use it only where you are allowed to.

## The rules this project is built around

1. **Authorized targets only.** Programs you are registered on, inside their published scope, under
   their rules of engagement. Anything else is off limits, whatever the tool lets you do.
2. **The scope file is a promise you make.** Fill `notes/scope.json` from the program page, not from
   guesses. With `requireConfirm: true` a human has to confirm the scope before live testing starts,
   and any later change to the scope needs a new confirmation.
3. **Never route around the scope guard.** If it blocks a request, the request doesn't happen. The
   hook can't see inside scripts that open their own connections, so the rule covers those too.
4. **Your own accounts and data only.** Prove impact with test accounts you control. Don't access,
   keep or change other users' data, and stop once the proof is met.
5. **No DoS, no mass scanning, no destructive actions**, unless a program explicitly allows a
   specific activity.
6. **Respect each program's AI clause.** Disclose AI assistance when a program asks for it. If a
   program restricts AI use, don't send its data to third-party models.
7. **A human submits every report.** The agent drafts and reviews; a person reads the report,
   reproduces what matters, and decides whether to send it. When form filling is on, the agent types
   the report into the platform's form in your own signed-in Chrome and stops before submit; the
   scope guard asks you before any click the agent describes as a submit.
8. **Keep private programs private.** Workspaces for private programs stay on your machine. Never
   push them to a public remote.

## What bountyproof deliberately doesn't do

- It doesn't submit reports to any platform. It can fill the form; pressing submit is yours.
- It doesn't ship mass scanners or exploit kits.
- It doesn't help disguise AI involvement in a report. The clarity pass makes a report shorter and
  more precise with the same facts; disclosure lines required by a program stay in.

If you find a way the tooling makes unsafe behavior easy, please report it (see SECURITY.md).
