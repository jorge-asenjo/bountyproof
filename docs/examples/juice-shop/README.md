# A real run: the demo lab

One pass of the full pipeline against the [demo lab](../../../lab/) (OWASP Juice Shop v20.3.0 on
`localhost`, a deliberately vulnerable app), with Claude Code and the bountyproof plugin, on
2026-10-28. Two test accounts registered by the hunter, nothing else.

## The funnel

```text
Evidence funnel - juice-shop-lab-hackerone

  hypotheses proposed    22  ##############################
  validated              17  #######################
  passed the judge       16  ######################
  submitted               0
  accepted                0

  dropped: DISCARDED 1, rejected 2
```

Juice Shop is vulnerable on purpose, so most leads hold up. On a real program the funnel is much
narrower.

## What each gate did

- **Scope guard.** Checked 153 requests. It blocked live testing until the hunter confirmed the scope,
  and it blocked a request that was missing the program's UA tag.
- **Validator.** Rejected two leads that looked plausible but didn't reproduce: input that turned out
  to be sanitised, and a template injection that the server escaped.
- **Evidence judge.** Passed 16, merged duplicates into 14 reports, and discarded one finding because
  the "unpaid order" it described is simulated payment by design. It also attached overclaim bans to
  findings that did pass, so the reports can't say more than the proof shows. A few examples:
  - an SQL injection that read the database, but whose report may not say "dumped all users";
  - a negative-quantity bug that credits an in-app balance, with no "theft" or real-money framing;
  - a password-hash leak, with no "account takeover" because cracking wasn't shown.
- **Review.** A fresh judge rated the first report READY.

## The report

[`report-H-001.md`](report-H-001.md): the clarity-pass version (v2), as the hunter would paste it.
Proven on the hunter's own second account, negative control first, captures saved under
`poc/H-001/` in the workspace, and impact limited to what the requests showed.
