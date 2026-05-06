---
name: False Positive
about: Report an endpoint that was incorrectly flagged as IDOR
title: "[FP] <endpoint>"
labels: false-positive
assignees: ''
---

## Endpoint Flagged
```
METHOD /api/path?parameter=VALUE
```

## Why It Is NOT Vulnerable
<!-- Explain the access control that prevents the IDOR -->

## Evidence
<!-- Screenshots or response showing proper 403/401 -->
