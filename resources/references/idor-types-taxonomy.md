# IDOR Types Taxonomy

> Complete classification of all IDOR vulnerability types.
> Use this to ensure you test every category on each target.

---

## Category 1 — Horizontal IDOR (Same Role)

User accesses another user's data at the **same privilege level**.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Read — no PII | View another user's public post | Low |
| Read — PII | View another user's invoice/address | High |
| Read — financial | Access payment records | High |
| Write — partial | Edit another user's profile field | High |
| Write — full | Overwrite another user's account | High |
| Delete | Delete another user's resource | High–Critical |

**Example:**
```
GET /api/invoice?invoice_id=12345   ← victim's ID used by attacker
```

---

## Category 2 — Vertical IDOR (Privilege Escalation)

Regular user accesses **admin-level** or higher-privileged resources.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Read admin data | View admin dashboard / user list | High |
| Perform admin action | Approve/reject other accounts | Critical |
| Role escalation | Change own role to admin via body | Critical |
| Access control bypass | Access `/admin/` endpoint as user | Critical |

**Example:**
```
GET /api/admin/users?user_id=1
POST /api/user/update  body: {"role": "admin"}
```

---

## Category 3 — IDOR in File/Media Access

Object references embedded in file paths or download URLs.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Direct file path | `/uploads/67890_contract.pdf` | High |
| Download by ID | `/api/download?file_id=VICTIM_ID` | High |
| Export by ID | `/api/export?report_id=VICTIM_ID` | High |
| Attachment in email link | Shared URL with predictable token | Medium–High |

---

## Category 4 — IDOR in POST/PUT Body

Object ID is inside the **request body**, not URL parameters.

| Sub-type | Example | Severity |
|----------|---------|----------|
| user_id in body | `{"user_id": "VICTIM_ID", "action": "view"}` | High |
| account_id swap | `{"account_id": "VICTIM_ID"}` | High |
| Nested object ID | `{"data": {"owner_id": "VICTIM_ID"}}` | High |

---

## Category 5 — IDOR in JSON/GraphQL APIs

Modern API patterns where IDs appear as query variables or arguments.

| Sub-type | Example | Severity |
|----------|---------|----------|
| GraphQL query argument | `invoice(id: "VICTIM_ID")` | High |
| GraphQL mutation | `updateProfile(userId: "VICTIM_ID")` | High |
| JSON-RPC call | `{"method": "getUser", "params": {"id": "VICTIM_ID"}}` | High |
| WebSocket message | `{"type": "subscribe", "channel_id": "VICTIM_ID"}` | Medium–High |

---

## Category 6 — IDOR in JWT / Cookie / Token

Object reference is **encoded inside an auth token**.

| Sub-type | Example | Severity |
|----------|---------|----------|
| JWT payload swap | Modify `sub` or `user_id` in JWT body | Critical |
| alg=none bypass | Remove JWT signature to forge payload | Critical |
| Base64 cookie | Decode → change user_id → re-encode | High |
| Weak HMAC secret | Brute-force JWT secret to sign forged token | Critical |

---

## Category 7 — Indirect / Reference-Based IDOR

Object is not referenced directly — accessed through another object.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Linked resource | Order belongs to victim, accessible via shared link ID | Medium |
| Relationship object | Comment ID links to victim's private post | Medium |
| Export/report reference | Shared report ID exposes victim's analytics | Medium–High |

---

## Category 8 — Blind IDOR

Attacker cannot see the data but can confirm access via **side effects**.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Email trigger | Attacker action sends email to victim | Medium |
| State change | Victim's order status changed silently | High |
| Same response length | 200 OK with same body length but victim's data | High |
| Timing difference | Slower response when valid ID used | Low–Medium |

---

## Category 9 — IDOR in Mass Assignment

Extra fields accepted in the body that override ownership or privilege.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Role field | `{"role": "admin"}` accepted in registration | Critical |
| Owner field | `{"owner_id": "VICTIM_ID"}` accepted in update | High |
| Verified flag | `{"is_verified": true}` bypasses verification | High |

---

## Category 10 — IDOR in Mobile APIs

APIs consumed by mobile apps often have weaker server-side controls.

| Sub-type | Example | Severity |
|----------|---------|----------|
| Hardcoded user_id | App sends `user_id` from local storage — tamperable | High |
| API key per user | API key used as object ID — guessable | High |
| Unprotected endpoints | Mobile-only endpoints without auth | High–Critical |

---

## Testing Priority Matrix

| Category | Frequency in Wild | Ease of Find | Priority |
|----------|-------------------|--------------|----------|
| Horizontal (GET) | Very High | Easy | 🔴 First |
| POST/PUT Body | High | Medium | 🔴 First |
| File Access | High | Easy | 🔴 First |
| JWT/Cookie | Medium | Hard | 🟡 Second |
| GraphQL | Medium | Medium | 🟡 Second |
| Vertical | Medium | Medium | 🟡 Second |
| Blind IDOR | Low | Hard | 🟢 Third |
| Mass Assignment | Medium | Easy | 🟡 Second |
| Mobile API | Medium | Medium | 🟡 Second |
