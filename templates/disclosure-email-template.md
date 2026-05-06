Subject: Responsible Disclosure — IDOR Vulnerability in [ENDPOINT]

To: security@[target.com]

Dear [Company] Security Team,

I am writing to responsibly disclose a security vulnerability I discovered
in your application. I have followed responsible disclosure practices and
have not shared this information with anyone else.

---

## Vulnerability Summary

**Type:** Insecure Direct Object Reference (IDOR)
**Endpoint:** `[ENDPOINT]`
**Parameter:** `[PARAMETER]`
**Severity:** High
**CVSS Score:** [SCORE] ([VECTOR])

---

## Description

An IDOR vulnerability exists in the `[ENDPOINT]` endpoint. By modifying the
`[PARAMETER]` value in the request, an authenticated user can access resources
belonging to other users without authorization.

The backend validates that the user is authenticated, but does not verify
that the requested object belongs to the authenticated user.

---

## Steps to Reproduce

1. Create two accounts — Account A (attacker) and Account B (victim)
2. As Account B, generate a [RESOURCE] and note its ID: `[PARAMETER]=VICTIM_ID`
3. Log in as Account A and send the following request:

```
GET [ENDPOINT]?[PARAMETER]=VICTIM_ID HTTP/1.1
Host: [TARGET]
Authorization: Bearer ATTACKER_TOKEN
```

4. Observe that Account A receives Account B's [RESOURCE] data including:
   - [DATA FIELD 1]
   - [DATA FIELD 2]

---

## Impact

This vulnerability allows any authenticated user to access [RESOURCE] data
belonging to other users. This exposes [PII/sensitive data] and could be
exploited at scale through ID enumeration.

---

## Recommended Fix

Add an ownership check before returning any resource:

```python
if resource.owner_id != current_user_id:
    return 403
```

Additional: implement rate limiting and replace sequential IDs with UUIDs.

---

## My Details

**Name:** [Your Name / Handle]
**Contact:** [Your Email]
**PGP Key:** [Optional]

I am available to provide additional details, PoC evidence, or to verify
the fix once implemented. I request a 90-day disclosure window before
publishing my findings publicly.

Thank you for your attention to this matter.

Regards,
[Your Name]
