# Pre-Submission Checklist — IDOR Bug Bounty

> Complete ALL items before submitting. A complete report = faster triage = faster reward.

---

## ✅ Vulnerability Validation

- [ ] Bug is **still reproducible** right now (re-test before submitting)
- [ ] Confirmed using **two separate test accounts** (attacker + victim)
- [ ] Attacker session receives **actual victim data**, not just 200 OK
- [ ] Tested both directions: attacker→victim AND victim→attacker
- [ ] Verified the endpoint is **in-scope** for the program

---

## ✅ Report Completeness

- [ ] Title is specific: names endpoint, parameter, and data exposed
- [ ] Summary is 2–3 sentences max
- [ ] Description explains **why** the check fails (root cause)
- [ ] Steps to reproduce are **numbered, clear, and self-contained**
- [ ] PoC includes the **full HTTP request** (attacker session)
- [ ] PoC includes the **full HTTP response** (victim data visible)
- [ ] Impact section includes a **realistic attacker scenario**
- [ ] CVSS score is included and justified
- [ ] Remediation includes **code-level fix** suggestion

---

## ✅ Evidence

- [ ] Screenshot(s) showing attacker receiving victim data
- [ ] Screenshot(s) showing your own ID returns different data
- [ ] Video recording (optional but highly recommended for complex flows)
- [ ] Raw HTTP request saved to `poc/requests/`

---

## ✅ Pre-Submit Checks

- [ ] Report has **no spelling or grammar errors**
- [ ] All placeholder text replaced (no `VICTIM_ID`, `YOUR_TOKEN` left in)
- [ ] Checked HackerOne / Bugcrowd for **duplicate reports** on same endpoint
- [ ] Program has **no existing known issue** for this endpoint
- [ ] Severity matches the program's **VRT (Vulnerability Rating Taxonomy)**
- [ ] Report does NOT include any **real user data** (only test account data)
- [ ] Rate limiting / enumeration impact is addressed in the Impact section

---

## ✅ Submission

- [ ] Attach all evidence files
- [ ] Set correct severity level in the platform
- [ ] Add relevant tags (IDOR, BOLA, Broken Access Control)
- [ ] Copy final report to `reports/submitted/`
- [ ] Update `IDOR-tracker.md` with submission date

---

## 🚀 After Submission

- [ ] Monitor for triage response (usually 3–7 days)
- [ ] Respond to any triager follow-up questions within 48 hours
- [ ] If accepted → move to `reports/accepted/` and update tracker
- [ ] If rejected → note reason in `reports/rejected/` and learn from it
