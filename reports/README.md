# Reports

Stores all bug bounty reports organized by status.

## Workflow

```
Draft → Submit → Accepted / Rejected
```

## Subfolders

| Folder | Purpose |
|--------|---------|
| `drafts/` | Work-in-progress reports — not yet submitted |
| `submitted/` | Reports sent to bug bounty programs |
| `accepted/` | Confirmed and rewarded vulnerabilities |
| `rejected/` | Declined, duplicate, or informative reports |

## Naming Convention

```
IDOR-[program]-[endpoint]-YYYY-MM-DD.md

Examples:
  IDOR-hackerone-billing-invoice-2026-05-06.md
  IDOR-bugcrowd-user-profile-2026-05-10.md
```

## Status Tracking

Update `IDOR-tracker.md` in the root whenever a report status changes.
