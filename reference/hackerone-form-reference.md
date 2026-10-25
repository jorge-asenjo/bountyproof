# HackerOne Form Reference

## Section 1: ASSET & WEAKNESS
| Field | Type | Notes |
|-------|------|-------|
| Asset* | Dropdown | From the program's structured scopes (URLs, wildcards, IPs, etc.) |
| Weakness* | Dropdown | CWE classification. Each program can customize the visible list |

## Section 2: TITLE
| Field | Type | Notes |
|-------|------|-------|
| Title* | Text input | Clear and concise. E.g. "IDOR in /api/v1/users/{id} allows accessing other users' data" |

## Section 3: VULNERABILITY INFORMATION
| Field | Type | Notes |
|-------|------|-------|
| Vulnerability Information* | Markdown editor | Full description + Steps to Reproduce + PoC |

Recommended sections:
- **Summary**: what the bug is and where it lives
- **Steps to Reproduce**: numbered steps to reproduce it
- **Proof of Concept**: curl commands, HTTP requests, code
- Screenshots/videos: upload as attachments and reference them in the text

Note: programs can have a report template that pre-fills this field with suggested sections. Follow
the program's template if it has one.

## Section 4: IMPACT
| Field | Type | Notes |
|-------|------|-------|
| Impact* | Markdown editor | SEPARATE field. Why this bug matters and what an attacker can do |

Don't mix it into the description. Concrete, realistic impact, not theoretical.

## Section 5: SEVERITY
| Field | Type | Notes |
|-------|------|-------|
| Severity | CVSS calculator (optional) | Some programs set it themselves |

CVSS 3.1 metrics:
- Attack Vector (AV): Network / Adjacent / Local / Physical
- Attack Complexity (AC): Low / High
- Privileges Required (PR): None / Low / High
- User Interaction (UI): None / Required
- Scope (S): Unchanged / Changed
- Confidentiality (C): None / Low / High
- Integrity (I): None / Low / High
- Availability (A): None / Low / High

## Section 6: ATTACHMENTS
| Field | Type | Notes |
|-------|------|-------|
| Attachments | File upload | Screenshots (PNG/JPEG), videos (file upload, NO external links) |

## Key differences from YesWeHack and Intigriti
- **Impact is a separate, required field** (on YWH it goes inside the description; Intigriti also keeps it separate)
- **Not present**: Endpoint, Vulnerable part, Part name, Payload as separate fields — all of that goes in Vulnerability Information
- **Weakness**: CWE dropdown, similar to YWH's Bug type but customizable per program
- **You can't edit after submitting** — make sure everything is correct before you submit
- **Report templates**: the program may have a pre-filled template with sections. Use it if it exists
- **Screenshots**: file upload, NO external links, NO {{YWH-RXXX}} syntax
- **Auth**: the API uses HTTP Basic (username:token), not Bearer
- **Program URL**: `https://hackerone.com/{handle}`
