1  # IDOR in Billing API Allows Viewing Other Users' Invoices

1. Summary - Fast Context In Two Or Three Sentences

## Summary

An Insecure Direct Object Reference (IDOR) exists in the `/api/billing/invoice` endpoint.
By changing the `invoice_id` parameter, an authenticated user can retrieve invoices
that belong to other customers, including their names, addresses, and payment details.

1. Description - Explain What Is Broken And Why

## Description

The billing API uses the `invoice_id` parameter to return invoice details.
The backend checks that the user is logged in, but it does not verify that the
requested invoice actually belongs to the logged in user.
As a result, any authenticated user can modify the `invoice_id` value and access
invoices generated for other accounts. These invoices contain personally identifiable
information (PII) such as full names, billing addresses, and payment amounts.
The issue exists because authorization is performed only at the session level,
without an ownership check on the requested resource.

1. Steps To Reproduce - Your Most Important Section

## Steps to Reproduce

1. Create two accounts:
   - Account A (attacker): `user1@example.com`
   - Account B (victim): `user2@example.com`
2. Log in as Account B and open any invoice from the billing page.
3. Intercept the request that loads the invoice and note the ID value:
   `GET /api/billing/invoice?invoice_id=12345`
4. Log out and then log in as Account A.
5. Send the same request as Account A, reusing the victim invoice ID:
   `GET /api/billing/invoice?invoice_id=12345`
6. Observe that Account A receives the full invoice details for Account B, including:
   - Customer name
   - Billing address
   - Amount paid
   - Invoice date

7. Proof Of Concept - Show, Do Not Just Tell

## Proof of Concept

### HTTP Request (attacker viewing victim invoice)

```http
GET /api/billing/invoice?invoice_id=12345 HTTP/1.1
Host: example.com
Cookie: session=attacker_session_token
```

### Response

```json
{
  "invoice_id": "12345",
  "user_id": "67890",
  "user_name": "Jane Doe",
  "billing_address": "123 Main St, City, State",
  "amount": "$299.99",
  "date": "2025-01-15"
}
```

1. Impact - Translate the Bug into Real Risk

## Impact

This vulnerability allows any authenticated user to:

- Access billing information belonging to other users
- Perform large scale enumeration of invoice IDs
- Collect names, addresses, and payment data at high volume
- Use harvested billing records for targeted phishing or identity theft

Realistic example: an attacker signs up for a free account, cycles through predictable
invoice IDs, and downloads thousands of invoices. The collected PII is monetized or
used in social engineering campaigns.

Estimated severity: High
Example CVSS: 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

1. Remediation - Help Them Fix It

## Remediation

Recommended fix:

Add an ownership check before returning invoice data. The backend must verify that
the invoice being requested belongs to the authenticated user.

Example logic:

```python
def get_invoice(invoice_id, user_id):
    invoice = db.get_invoice(invoice_id)

    if not invoice or invoice.user_id != user_id:
        return {"error": "Unauthorized"}, 403

    return invoice
```

**Additional recommendations:**- Implement rate limiting to prevent mass enumeration

- Use UUIDs instead of sequential IDs for invoices
- Add logging and alerting for unauthorized access attempts

```



```
