# Mobile API IDOR Testing Guide

> Mobile apps (Android/iOS) often consume REST APIs with weaker server-side controls.
> Use this guide to intercept mobile traffic and test for IDOR.

---

## 1. Setup — Intercept Mobile Traffic

### Android (Non-rooted)
1. Install Burp CA cert on device:
   - Export Burp cert: `Proxy → Options → Export CA certificate`
   - Push to phone, install under `Settings → Security → Install certificate`
2. Set phone WiFi proxy to your machine IP on port `8080`
3. For Android 7+: use **apk-mitm** or **objection** to bypass SSL pinning

### iOS
1. Install Burp CA cert via Safari at `http://burp`
2. Trust under `Settings → General → VPN & Device Management`
3. Set WiFi HTTP proxy to `127.0.0.1:8080`

### Alternative — Android Emulator
```bash
# Start emulator with proxy
emulator -avd Pixel_6 -http-proxy 127.0.0.1:8080
```

---

## 2. Extract API Endpoints from APK

```bash
# Decompile APK with apktool
apktool d target_app.apk -o output/

# Search for API endpoints
grep -r "api\|/v1\|/v2\|http" output/ --include="*.smali" | grep -i "url\|endpoint\|path"

# Decompile to Java with jadx
jadx target_app.apk -d jadx_output/
grep -r "/api/" jadx_output/ --include="*.java"
```

---

## 3. Common Mobile IDOR Patterns

### Pattern 1 — user_id from Local Storage
Mobile apps often store `user_id` locally and send it in every API request:
```http
POST /api/data/fetch HTTP/1.1
Host: api.example.com
Content-Type: application/json
X-Auth-Token: ATTACKER_TOKEN

{"user_id": "VICTIM_ID", "type": "profile"}
```

### Pattern 2 — Hardcoded Device/Account ID
```http
GET /api/v1/account/VICTIM_ACCOUNT_ID/settings HTTP/1.1
Host: api.example.com
Authorization: Bearer ATTACKER_TOKEN
X-Device-ID: some-device-id
```

### Pattern 3 — Unprotected Internal Endpoints
Mobile apps sometimes expose endpoints not linked in the web UI:
```
/api/internal/user/VICTIM_ID
/api/mobile/v1/profile?uid=VICTIM_ID
/api/app/invoice?id=VICTIM_ID
```

---

## 4. Tools for Mobile IDOR Testing

| Tool | Purpose | Install |
|------|---------|---------|
| **Burp Suite** | Intercept & replay HTTP | https://portswigger.net/burp |
| **apktool** | Decompile APK | `apt install apktool` |
| **jadx** | Decompile APK to Java | https://github.com/skylot/jadx |
| **objection** | Bypass SSL pinning at runtime | `pip install objection` |
| **apk-mitm** | Patch APK to trust user certs | `npm i -g apk-mitm` |
| **Frida** | Dynamic instrumentation / SSL unpin | https://frida.re |
| **MobSF** | Static + dynamic mobile app analysis | https://github.com/MobSF/Mobile-Security-Framework-MobSF |

---

## 5. SSL Pinning Bypass

### Using objection (Frida-based)
```bash
# Start objection on connected device
objection -g com.target.app explore

# Disable SSL pinning
android sslpinning disable
```

### Using apk-mitm (patch APK)
```bash
apk-mitm target_app.apk
# Installs patched APK that trusts user certificates
```

---

## 6. Quick Checklist — Mobile IDOR

- [ ] Intercept all mobile API traffic via Burp
- [ ] Search APK for hardcoded user IDs or endpoint patterns
- [ ] Test all endpoints that accept user/account/resource IDs
- [ ] Try swapping IDs in JSON body, URL params, and custom headers
- [ ] Check for unprotected `/internal/` or `/mobile/` endpoints
- [ ] Test both Android and iOS clients — may hit different endpoints
- [ ] Verify SSL pinning is bypassed before testing

---

## 7. Reporting Mobile IDOR

Same report format as REST IDOR. Add:
- **App version** tested
- **Platform** (Android X.X / iOS X.X)
- **How traffic was intercepted** (Burp + SSL unpin method)
- Raw HTTP request from Burp (not the app UI screenshot)
