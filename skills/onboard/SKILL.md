---
description: "Set up bountyproof on this machine - detect hardware, tools and phones, ask about platform accounts, devices and limits, and save the hunter profile every new workspace plans with."
disable-model-invocation: true
---

Onboard the user to bountyproof.

1. Detect the machine with the first form that works:
   - `bountyproof onboard --detect`
   - `python "${CLAUDE_PLUGIN_ROOT}/scripts/bountyproof.py" onboard --detect`

   Show the result in a few lines.
2. Ask, in one message, what detection can't tell. Offer the detected values as defaults:
   - platforms with an account (YesWeHack, Intigriti, HackerOne) and the username on each;
   - devices to test with (Android phone, iPhone, Mac);
   - what to hunt (web apps, APIs, mobile apps, source-available code);
   - anything they can't do (corporate email accounts, KYC with identity documents, real purchases);
   - hours a week, and the smallest top bounty worth their time.
3. Save the profile with the same command plus `--yes` and one flag per answer, for example:
   `bountyproof onboard --yes --platform hackerone:jdoe --platform ywh --device android --focus web --focus api --focus mobile --cant kyc --hours 8 --min-bounty 500`.
   Use `none` for an empty answer (`--device none`).
4. Show the "What you can hunt" table it prints. For each `partial` or `missing` line the user cares
   about, give the one install step that fixes it.
5. Phone alerts need tokens typed in privately, so don't run Radar here. Tell the user to run
   `bountyproof radar init` in their own terminal: it creates a private GitHub repo, sets the secrets
   and sends a test alert to the ntfy app.
