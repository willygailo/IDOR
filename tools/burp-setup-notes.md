# Burp Suite Setup for IDOR Hunting

---

## 1. Project Setup

1. Open Burp Suite → **New project in memory**
2. Go to **Proxy → Intercept → Off**
3. Set browser proxy to `127.0.0.1:8080`
4. Install Burp CA cert in browser for HTTPS

---

## 2. Scope Configuration

1. **Target → Scope → Add**
2. Add: `https://target.example.com`
3. Enable **"Use advanced scope control"**
4. In Proxy settings: **"Drop all out-of-scope requests"**

---

## 3. Two Sessions (Attacker + Victim)

1. Log in as **Victim** → copy session token → save to notepad
2. Log in as **Attacker** → Burp uses this in Proxy
3. In **Repeater**: paste victim token manually to test IDOR

---

## 4. Key Extensions (BApp Store)

| Extension | Purpose |
|-----------|---------|
| **Autorize** | Auto re-sends every request with low-priv session — flags IDOR |
| **Agartha** | Privilege escalation detection |
| **Logger++** | Advanced request/response logging |
| **JSON Beautifier** | Formats JSON for easier reading |

### Autorize Setup

1. Install Autorize from BApp Store
2. Log in as low-priv user → copy session header
3. Paste into Autorize **"Fetch requests with the following headers"**
4. Browse app as high-priv user
5. **Red** = IDOR confirmed, **Green** = blocked, **Yellow** = investigate

---

## 5. Intruder for ID Enumeration

1. Intercept request → **Send to Intruder**
2. Highlight ID value → **Add §**
3. Payloads → **Numbers**: From `1`, To `10000`, Step `1`
4. Grep-Match: add victim's unique data (e.g. email)
5. Start → sort by **Length** to find hits

---

## 6. Repeater Tips

- Keep **two tabs**: attacker token vs victim token
- Send same request from both → compare responses
- Right-click → **"Copy as curl"** to save PoC

---

## 7. Quick Workflow

```
1. Browse as Victim → note all request IDs in Proxy history
2. Find endpoints with IDs in Target → Site Map
3. Send to Repeater → swap ID + swap token to attacker
4. Send → victim data appears → IDOR confirmed
5. Save request → screenshot → write report
```

---

## 8. Useful Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+Shift+B` | Send to Comparer |
| `F12` | Toggle Intercept |
