# YesWeHack Form Reference

## Section 1: BUG DETAILS
| Field | Type | Notes |
|-------|------|-------|
| Bug type* | Dropdown | "Category - Subcategory (CWE-XXX)" |
| Scope* | Dropdown | The program's scope entries (domains, apps or repo URLs) |
| Endpoint* | Text | Vulnerable path, e.g. `/api/v1/orders/{id}` |
| Vulnerable part* | Dropdown | HTTP Response, HTTP Parameter, etc. |
| Part name* | Text | The exact part (parameter, header, field name) |
| Payload* | Text | The concrete value used, e.g. `orderId=1002` |
| Technical environment* | Text | YOUR actual test environment |
| Application fingerprint | Text | Target version, if known |
| CVE | Text | CVE-YYYY-NNNN (optional) |
| Impact | Dropdown | Sensitive Data Exposure, etc. |
| IPs used* | Text | Your IP (the GET MY IP button fills it in) |

## Section 2: CVSS 3.1
AV, AC, PR, UI, S, C, I, A -> the vector is calculated automatically

## Section 3: DESCRIPTION
- Markdown supported; write in English
- Sections: Description, Exploitation, PoC, Risk, Remediation
- Code blocks: ```bash, ```java, ```http, etc.
- Inline screenshots: {{YWH-RXXX}} (double braces)
- Attachments: UPLOAD button, JPEG/PNG 10MB max, MP4/WEBM 100MB max

## Section 4: BUG CHAIN
Optional checkbox to chain this report with another bug
