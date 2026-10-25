# Intigriti Form Reference

Captured from a live submission form. The assets are examples (they change per program); the rest of
the form is fixed.

## Section 1: GENERAL
| Field | Type | Notes |
|-------|------|-------|
| Title* | Text input | Descriptive, not generic. E.g. "IDOR in /api/users allows access to other users' data" |
| Select asset* | Selector with filters | Filter by Tier and Type. Options: URLs, wildcards, etc. Pick the affected asset |
| Endpoint / vulnerable component | Text input (optional) | Placeholder: "https://example.com/vulnerable" |

## Section 2: TYPE
| Field | Type | Notes |
|-------|------|-------|
| Type* | Searchable selector | Categories: Access Control Issues, Injection, Broken Authentication, XSS, Misconfiguration, etc. |

Main categories:
- Access Control Issues (IDOR, Path Traversal, Privilege Escalation, Improper Access Control, Forced Browsing...)
- Injection (SQLi, Command Injection, SSTI, NoSQL, LDAP, XPath, XML, CSV, SOAP...)
- Cross site scripting (Blind, Reflected, Stored, DOM-Based, Self XSS, XSSI)
- Broken Authentication (Session Fixation, Insufficient Session Expiration, Improper Authentication, Brute Force...)
- Broken Access Control (Horizontal/Vertical Privilege Escalation, IDOR, Path Traversal, Forced Browsing...)
- Misconfiguration (Directory Listing, Error Message Exposure, Generic...)
- XML External Entities (XXE)
- Insecure deserialisation
- Vulnerable components (Broken Crypto, Violation of Secure Design, Integer Overflow)
- Cryptographic issues (Certificate Validation, Reversible Hash, Inadequate Encryption, Missing Encryption...)
- Memory Management (Use After Free, Out-of-bounds Write, Memory Corruption, Null Pointer, Double Free...)
- Generative AI & LLMs (Prompt Injection, Insecure Output, Training Data Poisoning, Model DoS...)
- Mobile (all the categories above + SSL Pinning, Mobile Misconfiguration)
- Other (RCE, SSRF, CSRF, Open Redirect, File Upload, Race Condition, Request Smuggling, Business Logic, Subdomain Takeover, Cache Poisoning/Deception, CRLF, HPP, etc.)

## Section 3: SEVERITY (CVSS 3.1)
| Metric | Options |
|--------|---------|
| Attack Vector (AV) | Network / Adjacent / Local / Physical |
| Attack Complexity (AC) | Low / High |
| Privileges Required (PR) | None / Low / High |
| User Interaction (UI) | None / Required |
| Scope (S) | Unchanged / Changed |
| Confidentiality (C) | None / Low / High |
| Integrity (I) | None / Low / High |
| Availability (A) | None / Low / High |

## Section 4: DETAILS
| Field | Type | Notes |
|-------|------|-------|
| Attachments | Upload button | Screenshots (PNG/JPEG), videos, etc. |
| Proof of concept / description* | Rich text editor | Max 30,000 characters. Supports markdown/rich text |

Recommended sections in the description:
- **Description**: what the bug is and where it lives
- **Steps to Reproduce**: numbered steps to reproduce it
- **PoC**: commands, requests, code
- Screenshots: upload as attachments and reference them in the text

## Section 5: IMPACT
| Field | Type | Notes |
|-------|------|-------|
| Impact* | Rich text editor | Max 15,000 characters. Real, concrete impact |
| Recommended solution | Rich text editor (optional) | Max 15,000 characters. Short, 1-2 lines |

## Section 6: TEST INFO
| Field | Type | Notes |
|-------|------|-------|
| IP address used | Input (optional) | "Autofill my current IP" button |
| Unique conditions | Textarea (optional) | Max 1,500 characters |
| Severity justification | Textarea | Max 1,500 characters |
| Test information | Textarea (optional) | Max 1,500 characters. IP, accounts used, etc. |

## Key differences from YesWeHack
- **Assets have Tiers**: each asset has a Tier (it affects the reward). YWH uses a plain Scope field
- **Separate fields**: Impact and Recommended solution are their own fields (not inside the description)
- **Severity justification**: dedicated field (on YWH it goes in the description)
- **Not present**: Vulnerable part, Part name, Payload as separate fields - all of that goes in the description/PoC
- **Screenshots**: upload as attachments; there is NO {{YWH-RXXX}} syntax
- **Character limits**: description 30k, impact 15k, solution 15k, textareas 1.5k
