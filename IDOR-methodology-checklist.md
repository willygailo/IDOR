# IDOR Testing Methodology Checklist

> Complete this checklist for every target application. Check off each step as you go.

---

## Phase 1 — Reconnaissance & Scope

- [ ] Read the program's full scope and out-of-scope definitions
- [ ] Identify all API endpoints (use Burp Proxy, JS file analysis, Swagger/OpenAPI docs)
- [ ] Map all endpoints that accept an object identifier as a parameter
- [ ] Note which IDs appear sequential, numeric, or UUIDs
- [ ] Identify authenticated vs. unauthenticated endpoints

---

## Phase 2 — Account Setup

- [ ] Create at least **two test accounts** (attacker + victim)
- [ ] If roles exist, test across different roles: user, admin, moderator
- [ ] Generate objects (invoices, orders, profiles, messages) in victim account
- [ ] Note all object IDs created by the victim account

---

## Phase 3 — IDOR Testing

### 3a — GET-based IDOR (horizontal)
- [ ] Swap victim object ID while authenticated as attacker
- [ ] Test direct URL access (no session), object ID swap
- [ ] Try predictable ID enumeration (sequential integers)
- [ ] Test all GET endpoints: `/api/resource/{id}`, `/api/resource?id=X`

### 3b — POST/PUT/PATCH/DELETE IDOR (write operations)
- [ ] Modify request body: swap `user_id`, `account_id`, `owner_id`
- [ ] Try deleting victim resources via attacker session
- [ ] Try updating victim profile/data via attacker session

### 3c — Vertical Privilege Escalation
- [ ] Swap `role` field in request body (`user` → `admin`)
- [ ] Access admin endpoints using a normal user session
- [ ] Modify `user_id` to an admin account ID

### 3d — Indirect IDOR
- [ ] Test endpoints where ID is embedded in JWT or cookie
- [ ] Check if changing encrypted/encoded values reveals IDOR
- [ ] Test reference IDs in nested JSON bodies

### 3e — Blind IDOR
- [ ] Trigger actions where response is same regardless (no body diff)
- [ ] Detect by side effects: emails sent, data modified, logs created

---

## Phase 4 — Impact Validation

- [ ] Confirm attacker receives victim's actual data (not just 200 OK)
- [ ] Identify what PII or sensitive data is exposed
- [ ] Test mass enumeration: loop through 20–50 IDs to confirm scale
- [ ] Assess if write IDOR can cause data corruption or deletion

---

## Phase 5 — Documentation

- [ ] Save full HTTP request (Burp "Save item") to `poc/requests/`
- [ ] Record video or screenshot of the PoC
- [ ] Fill out `templates/idor-report-template.md`
- [ ] Calculate CVSS score
- [ ] Update `IDOR-tracker.md`
- [ ] Save final report to `reports/drafts/`

---

## Phase 6 — Submission

- [ ] Final proofread of the report
- [ ] Attach all evidence (screenshots, video, request/response)
- [ ] Submit to program
- [ ] Move report to `reports/submitted/`
- [ ] Update tracker with submission date and status

---

## Common IDOR Parameter Names to Test

```
id, user_id, account_id, invoice_id, order_id, ticket_id,
document_id, file_id, message_id, report_id, profile_id,
customer_id, session_id, token, uid, uuid, ref, key, resource_id
```

---

## CVSS Quick Reference (IDOR)

| Scenario | Score | Vector |
|----------|-------|--------|
| Read-only, authenticated, no PII | ~4.3 | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N |
| Read PII (names, addresses) | ~6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| Write/delete victim data | ~8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Unauthenticated + PII | ~9.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
