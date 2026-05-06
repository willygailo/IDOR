# PoC (Proof of Concept)

Contains all evidence materials for IDOR findings.

## Subfolders

| Folder | Contents |
|--------|----------|
| `scripts/` | Python automation tools for IDOR testing |
| `requests/` | Raw HTTP request samples (.http files) |
| `screenshots/` | Visual evidence (screenshots, recordings) |

## Scripts Available

| Script | Purpose | Usage |
|--------|---------|-------|
| `idor_enum.py` | GET parameter enumerator | `python3 idor_enum.py --url URL --param id --start 1 --end 500` |
| `post_idor_tester.py` | POST/PUT/PATCH body tester | `python3 post_idor_tester.py --url URL --body '{"user_id":1}' --param user_id` |
| `threaded_idor_enum.py` | Fast concurrent enumerator | `python3 threaded_idor_enum.py --url URL --param id --threads 20` |
| `blind_idor_differ.py` | Blind IDOR response differ | `python3 blind_idor_differ.py --url URL --victim-token T1 --attacker-token T2` |
| `jwt_idor_tester.py` | JWT/Cookie token tester | `python3 jwt_idor_tester.py --url URL --mode jwt --token JWT --field user_id --victim-id 456` |
| `js_endpoint_extractor.py` | JS file endpoint extractor | `python3 js_endpoint_extractor.py --target https://target.com` |

## HTTP Request Samples

| File | Method | Use Case |
|------|--------|---------|
| `sample_get_idor.http` | GET | URL parameter IDOR |
| `sample_post_idor.http` | POST | JSON body IDOR |
| `sample_put_patch_idor.http` | PUT/PATCH | Update IDOR |
| `sample_delete_idor.http` | DELETE | Delete IDOR |
| `sample_graphql_idor.http` | POST | GraphQL query/mutation IDOR |
| `sample_file_upload_idor.http` | GET/POST | File access IDOR |
