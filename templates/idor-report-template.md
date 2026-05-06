# [VULNERABILITY TITLE] — IDOR in [Endpoint]

---

## Summary

> One to three sentences. Name the endpoint, the parameter, and what data leaks.

An Insecure Direct Object Reference (IDOR) exists in `[ENDPOINT]`.
By manipulating the `[PARAMETER]` value, an authenticated user can access
resources belonging to other users, exposing `[DATA TYPE]`.

---

## Description

> Explain what is broken and why the authorization check fails.

The `[ENDPOINT]` endpoint accepts `[PARAMETER]` as input and returns
`[RESOURCE]` without verifying that the requesting user owns it.
The backend only validates that the session is authenticated, not that
the session belongs to the owner of the requested object.

This means any authenticated user can enumerate or directly access
`[RESOURCE]` belonging to arbitrary accounts.

---

## Steps to Reproduce

1. Create two accounts:
   - **Account A (attacker):** `attacker@example.com`
   - **Account B (victim):** `victim@example.com`
2. Log in as **Account B** and perform the action that generates the resource.
3. Intercept the request using Burp Suite. Note the `[PARAMETER]` value:
   ```
   GET [ENDPOINT]?[PARAMETER]=VICTIM_ID
   ```
4. Log out and log in as **Account A**.
5. Replay the same request using **Account A's session** and the victim's ID:
   ```
   GET [ENDPOINT]?[PARAMETER]=VICTIM_ID
   ```
6. Observe that Account A receives Account B's data.

---

## Proof of Concept

### HTTP Request (Attacker's Session)

```http
GET [ENDPOINT]?[PARAMETER]=VICTIM_ID HTTP/1.1
Host: [TARGET]
Cookie: session=[ATTACKER_SESSION_TOKEN]
Authorization: Bearer [ATTACKER_TOKEN]
```

### Response

```json
{
  "[PARAMETER]": "VICTIM_ID",
  "user_id": "[VICTIM_USER_ID]",
  "[DATA_FIELD_1]": "[VALUE]",
  "[DATA_FIELD_2]": "[VALUE]"
}
```

> Attach screenshots or video recording as evidence.

---

## Impact

This vulnerability allows any authenticated user to:

- Access `[DATA TYPE]` belonging to other users
- Perform large-scale enumeration using sequential or predictable IDs
- Harvest PII at volume for phishing, identity theft, or fraud

**Realistic scenario:** An attacker signs up for a free account, iterates
through predictable `[PARAMETER]` values, and collects thousands of
`[DATA TYPE]` records without detection.

**Severity:** [Critical / High / Medium]
**CVSS Score:** `[SCORE]` (`[CVSS_VECTOR]`)

---

## Remediation

Add an **object-level ownership check** before returning any resource:

```python
def get_resource(resource_id, current_user_id):
    resource = db.get(resource_id)

    if not resource or resource.owner_id != current_user_id:
        return {"error": "Unauthorized"}, 403

    return resource
```

**Additional recommendations:**

- Implement rate limiting to prevent mass enumeration
- Replace sequential integer IDs with UUIDs (non-guessable)
- Log and alert on unauthorized access attempts
- Apply OWASP API Security Top 10 — API1:2023 (Broken Object Level Authorization)

---

## References

- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger IDOR](https://portswigger.net/web-security/access-control/idor)

---

*Report generated: [DATE]*
*Program: [BUG BOUNTY PLATFORM / PROGRAM NAME]*
