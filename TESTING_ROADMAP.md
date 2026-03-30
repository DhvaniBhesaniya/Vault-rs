# RustVault — Complete Testing Roadmap

A step-by-step guide to start, test, and verify every feature of RustVault.

---

## Table of Contents

1. [Prerequisites & Setup](#1-prerequisites--setup)
2. [Start the Infrastructure](#2-start-the-infrastructure)
3. [Build & Run the Server](#3-build--run-the-server)
4. [Phase 1 — Health Checks](#4-phase-1--health-checks)
5. [Phase 2 — Public Tools (No Auth)](#5-phase-2--public-tools-no-auth)
6. [Phase 3 — Understanding the Crypto Flow](#6-phase-3--understanding-the-crypto-flow)
7. [Phase 4 — User Registration](#7-phase-4--user-registration)
8. [Phase 5 — User Login](#8-phase-5--user-login)
9. [Phase 6 — Token Refresh](#9-phase-6--token-refresh)
10. [Phase 7 — Vault CRUD](#10-phase-7--vault-crud)
11. [Phase 8 — Folders](#11-phase-8--folders)
12. [Phase 9 — Trash & Restore](#12-phase-9--trash--restore)
13. [Phase 10 — Session Management & Logout](#13-phase-10--session-management--logout)
14. [Phase 11 — Error & Edge Case Testing](#14-phase-11--error--edge-case-testing)
15. [Phase 12 — Security Header Verification](#15-phase-12--security-header-verification)
16. [Phase 13 — Database Verification](#16-phase-13--database-verification)
17. [Cheat Sheet — All Variables](#17-cheat-sheet--all-variables)

---

## 1. Prerequisites & Setup

### Install required tools

```bash
# Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Docker (for MongoDB)
# See: https://docs.docker.com/engine/install/

# Python 3 + crypto libs (for the test helper script)
pip install argon2-cffi cryptography

# jq (optional, for nicer JSON output)
sudo apt install jq    # Debian/Ubuntu
```

### Copy the environment file

```bash
cd /home/dhvani/personal_work/rust_project_for_portfolio/Vault-rs
cp .env.example .env
```

The defaults are fine for local development. No changes needed.

---

## 2. Start the Infrastructure

### Start MongoDB via Docker Compose

```bash
docker compose up -d
```

Verify it's running:

```bash
docker compose ps
# Should show rustvault-mongo as "running"

# Quick connectivity test:
docker exec rustvault-mongo mongosh --eval "db.runCommand({ping:1})"
```

---

## 3. Build & Run the Server

```bash
# Build (first time takes a few minutes)
cargo build

# Run the server
cargo run
```

You should see:
```
INFO vault_rs: Connecting to MongoDB at mongodb://localhost:27017
INFO vault_rs: Connected to MongoDB database: rustvault
INFO vault_rs: Ensuring MongoDB indexes...
INFO vault_rs: RustVault server starting on 0.0.0.0:8080
```

> **Tip:** Keep this terminal open. Open a NEW terminal for the curl commands below.

---

## 4. Phase 1 — Health Checks

**Goal:** Verify the server is running and connected to MongoDB.

### 4.1 Basic health check

```bash
curl -s http://localhost:8080/api/v1/health | jq
```

**Expected:**
```json
{
  "success": true,
  "data": {
    "status": "ok",
    "version": "0.1.0"
  },
  "meta": { "timestamp": "...", "request_id": null }
}
```

### 4.2 Readiness check (verifies DB connectivity)

```bash
curl -s http://localhost:8080/api/v1/health/ready | jq
```

**Expected:** Same shape with `"status": "ready"`.

### 4.3 Check response headers

```bash
curl -sI http://localhost:8080/api/v1/health
```

**Verify you see:**
- `x-request-id: <some-uuid>`
- `strict-transport-security: max-age=31536000; ...`
- `x-content-type-options: nosniff`
- `x-frame-options: DENY`

> **What you learned:** The server boots, connects to MongoDB, and applies security headers + request ID middleware globally.

---

## 5. Phase 2 — Public Tools (No Auth)

**Goal:** Test endpoints that work WITHOUT any authentication.

### 5.1 Generate a random password

```bash
curl -s -X POST http://localhost:8080/api/v1/tools/generate-password \
  -H "Content-Type: application/json" \
  -d '{"length": 24, "uppercase": true, "lowercase": true, "numbers": true, "symbols": true}' | jq
```

**Expected:** `{ "success": true, "data": { "password": "xK#9m..." } }`

Try different options:
```bash
# Numbers only, 8 chars
curl -s -X POST http://localhost:8080/api/v1/tools/generate-password \
  -H "Content-Type: application/json" \
  -d '{"length": 8, "uppercase": false, "lowercase": false, "numbers": true, "symbols": false}' | jq

# Default (no body — uses defaults)
curl -s -X POST http://localhost:8080/api/v1/tools/generate-password \
  -H "Content-Type: application/json" \
  -d '{}' | jq
```

### 5.2 Generate a passphrase

```bash
curl -s -X POST http://localhost:8080/api/v1/tools/generate-passphrase \
  -H "Content-Type: application/json" \
  -d '{"num_words": 5, "separator": "-", "capitalize": true, "include_number": true}' | jq
```

**Expected:** `{ "data": { "passphrase": "Brave-Cotton-Eagle-Clinic-Album-472" } }`

### 5.3 Check breach (HIBP k-Anonymity)

This calls the real Have I Been Pwned API using k-Anonymity (only sends first 5 chars of SHA-1 hash).

```bash
# SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
curl -s -X POST http://localhost:8080/api/v1/tools/check-breach \
  -H "Content-Type: application/json" \
  -d '{"sha1_hash": "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"}' | jq
```

**Expected:** `{ "data": { "breached": true, "count": <some large number> } }`

Now test with a likely-clean hash:
```bash
# SHA-1 of a random UUID (almost certainly not breached)
RANDOM_HASH=$(echo -n "$(uuidgen)" | sha1sum | awk '{print toupper($1)}')
curl -s -X POST http://localhost:8080/api/v1/tools/check-breach \
  -H "Content-Type: application/json" \
  -d "{\"sha1_hash\": \"$RANDOM_HASH\"}" | jq
```

**Expected:** `{ "data": { "breached": false, "count": 0 } }`

> **What you learned:** Public tool endpoints work without authentication. The breach check uses real k-Anonymity — only a 5-char prefix is sent to HIBP, so nobody (not even HIBP) knows the full password hash.

---

## 6. Phase 3 — Understanding the Crypto Flow

**This is the most important section to understand before testing auth.**

RustVault uses **zero-knowledge encryption**. The server NEVER sees your master password or your actual vault data. Here's what happens:

### Registration (what the CLIENT does):

```
Master Password: "MyMasterPassword123!"
Email: "test@rustvault.dev"

Step 1: master_key        = Argon2id(password, salt=email)      → 32 bytes
Step 2: master_pw_hash    = HKDF(password, salt=master_key,
                                 info="master_password_hash")    → 32 bytes
Step 3: symmetric_key     = random(32 bytes)                     → 32 bytes
Step 4: protected_sym_key = AES-GCM(master_key, symmetric_key)  → encrypted blob
Step 5: Send to server:   {email, base64(master_pw_hash), base64(protected_sym_key), ...}
```

### What the SERVER does:

```
Step 6: stored_hash = Argon2id(master_pw_hash)   ← hashes the hash AGAIN
Step 7: Stores stored_hash + protected_sym_key in MongoDB
```

The server never has the master_key or symmetric_key.

### Generate test credentials with our helper:

```bash
cd /home/dhvani/personal_work/rust_project_for_portfolio/Vault-rs
python3 scripts/test_crypto_helper.py test@rustvault.dev "MyMasterPassword123!"
```

This will:
- Compute all the crypto values
- Print ready-to-use `curl` commands
- Save credentials to `scripts/test_credentials.json`

> **Key takeaway:** In a real client (React, mobile app, CLI), all this crypto happens transparently. For testing with curl, you need this helper to generate the correct values.

---

## 7. Phase 4 — User Registration

**Goal:** Create a new account.

### 7.1 Generate credentials and register

```bash
# Run the helper (outputs curl commands)
python3 scripts/test_crypto_helper.py test@rustvault.dev "MyMasterPassword123!"

# Copy and paste the REGISTER curl command from the output, OR:
# Use the values from scripts/test_credentials.json manually
```

**Expected response:**
```json
{
  "success": true,
  "data": {
    "user_id": "...",
    "email": "test@rustvault.dev",
    "message": "Account created successfully"
  }
}
```

**Save the user_id:**
```bash
export USER_ID="<user_id from response>"
```

### 7.2 Try registering the same email again

```bash
# Run the SAME register curl again
```

**Expected:** HTTP 409 Conflict
```json
{
  "success": false,
  "error": {
    "code": "CONFLICT",
    "message": "Conflict: An account with this email already exists"
  }
}
```

### 7.3 Try registering with invalid data

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "not-an-email", "name": "", "master_password_hash": "", "protected_symmetric_key": "x", "protected_symmetric_key_nonce": "x"}' | jq
```

**Expected:** HTTP 422 validation error.

> **What you learned:** Registration stores a double-hashed master password hash and the encrypted symmetric key. Duplicate emails are rejected. Validation works.

---

## 8. Phase 5 — User Login

**Goal:** Authenticate and receive JWT tokens + encrypted keys.

### 8.1 Login with correct credentials

```bash
# Use the LOGIN curl from the helper output, OR:
# Get master_pw_hash_b64 from scripts/test_credentials.json

curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@rustvault.dev",
    "master_password_hash": "<master_pw_hash_b64 from helper>",
    "device_name": "Test CLI"
  }' | jq
```

**Expected response:**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900,
    "protected_symmetric_key": "...",
    "protected_symmetric_key_nonce": "...",
    "user_id": "...",
    "email": "test@rustvault.dev",
    "name": "Test User",
    "two_factor_required": false,
    "kdf_memory_kb": 65536,
    "kdf_iterations": 3,
    "kdf_parallelism": 4
  }
}
```

**IMPORTANT — Save tokens for all subsequent requests:**
```bash
export TOKEN="<access_token from response>"
export REFRESH_TOKEN="<refresh_token from response>"
```

### 8.2 Try login with wrong password hash

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@rustvault.dev",
    "master_password_hash": "dGhpcyBpcyBhIHdyb25nIGhhc2g=",
    "device_name": "Bad Client"
  }' | jq
```

**Expected:** HTTP 401 `"Invalid email or password"`

### 8.3 Try login with non-existent email

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "nobody@example.com",
    "master_password_hash": "dGhpcyBpcyBhIHdyb25nIGhhc2g=",
    "device_name": "Test"
  }' | jq
```

**Expected:** HTTP 401 `"Invalid email or password"` (same message — no email enumeration leakage).

> **What you learned:** Login verifies the double-hashed master password hash, returns JWT tokens and the encrypted symmetric key. Wrong credentials give a generic error (no info leakage). Failed attempts are tracked.

---

## 9. Phase 6 — Token Refresh

**Goal:** Get new access + refresh tokens using the refresh token.

### 9.1 Refresh the token

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq
```

**Expected:**
```json
{
  "data": {
    "access_token": "eyJ...(new)...",
    "refresh_token": "eyJ...(new)...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**Update your tokens (token rotation — old refresh token is now revoked):**
```bash
export TOKEN="<new access_token>"
export REFRESH_TOKEN="<new refresh_token>"
```

### 9.2 Try using the OLD refresh token again

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<old_refresh_token>"}' | jq
```

**Expected:** HTTP 401 — old token is revoked (refresh token rotation).

> **What you learned:** Refresh token rotation is working. Each refresh token can only be used ONCE, then it's invalidated. This prevents replay attacks.

---

## 10. Phase 7 — Vault CRUD

**Goal:** Create, read, update, and delete encrypted vault items.

> **Reminder:** All `name_encrypted` and `data_encrypted` values are encrypted by the CLIENT with the symmetric key. The server stores opaque ciphertext.

For testing, we just need any base64 string — the server doesn't validate the encryption, it just stores blobs.

### 10.1 Create a vault item

```bash
curl -s -X POST http://localhost:8080/api/v1/vault/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "item_type": "login",
    "name_encrypted": "dGVzdCBuYW1lIGVuY3J5cHRlZA==",
    "data_encrypted": "dGVzdCBkYXRhIGVuY3J5cHRlZA==",
    "nonce": "dGVzdG5vbmNl",
    "favorite": false,
    "reprompt": false,
    "tags": ["github", "work"]
  }' | jq
```

**Save the item ID:**
```bash
export ITEM_ID="<id from response>"
```

### 10.2 Create more items (different types)

```bash
# A credit card
curl -s -X POST http://localhost:8080/api/v1/vault/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "item_type": "card",
    "name_encrypted": "Y3JlZGl0IGNhcmQ=",
    "data_encrypted": "Y2FyZCBkYXRhIGVuY3J5cHRlZA==",
    "nonce": "Y2FyZG5vbmNl",
    "favorite": true,
    "tags": ["finance"]
  }' | jq

# A secure note
curl -s -X POST http://localhost:8080/api/v1/vault/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "item_type": "secure_note",
    "name_encrypted": "c2VjcmV0IG5vdGU=",
    "data_encrypted": "bm90ZSBjb250ZW50",
    "nonce": "bm90ZW5vbmNl",
    "tags": ["personal"]
  }' | jq
```

### 10.3 List all vault items

```bash
curl -s http://localhost:8080/api/v1/vault/items \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** Array of all your items with pagination metadata.

### 10.4 List with pagination

```bash
# Page 1, 2 items per page
curl -s "http://localhost:8080/api/v1/vault/items?page=1&per_page=2" \
  -H "Authorization: Bearer $TOKEN" | jq

# Page 2
curl -s "http://localhost:8080/api/v1/vault/items?page=2&per_page=2" \
  -H "Authorization: Bearer $TOKEN" | jq
```

### 10.5 Get a single item

```bash
curl -s http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Authorization: Bearer $TOKEN" | jq
```

### 10.6 Update an item

```bash
curl -s -X PUT http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name_encrypted": "dXBkYXRlZCBuYW1l",
    "favorite": true,
    "tags": ["github", "work", "updated"]
  }' | jq
```

**Verify:** The `updated_at` timestamp changed, `favorite` is now `true`, tags updated.

### 10.7 Get the item again to confirm update

```bash
curl -s http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Authorization: Bearer $TOKEN" | jq
```

### 10.8 Try accessing without auth

```bash
curl -s http://localhost:8080/api/v1/vault/items | jq
```

**Expected:** HTTP 401 `"Missing Authorization header"`

### 10.9 Try accessing with invalid token

```bash
curl -s http://localhost:8080/api/v1/vault/items \
  -H "Authorization: Bearer invalid.token.here" | jq
```

**Expected:** HTTP 401 `"Invalid token"`

### 10.10 Try accessing a non-existent item

```bash
curl -s http://localhost:8080/api/v1/vault/items/000000000000000000000000 \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** HTTP 404 `"Vault item not found"`

> **What you learned:** Full CRUD on vault items works. Auth middleware protects all routes. Pagination works. The server stores encrypted blobs — it has no idea what's inside.

---

## 11. Phase 8 — Folders

**Goal:** Organize vault items into folders.

### 11.1 Create a folder

```bash
curl -s -X POST http://localhost:8080/api/v1/vault/folders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name_encrypted": "V29yayBGb2xkZXI="}' | jq
```

**Save:**
```bash
export FOLDER_ID="<id from response>"
```

### 11.2 Create a subfolder

```bash
curl -s -X POST http://localhost:8080/api/v1/vault/folders \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"name_encrypted\": \"U3ViZm9sZGVy\", \"parent_folder_id\": \"$FOLDER_ID\"}" | jq
```

### 11.3 List folders

```bash
curl -s http://localhost:8080/api/v1/vault/folders \
  -H "Authorization: Bearer $TOKEN" | jq
```

### 11.4 Rename a folder

```bash
curl -s -X PUT http://localhost:8080/api/v1/vault/folders/$FOLDER_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name_encrypted": "UmVuYW1lZCBGb2xkZXI="}' | jq
```

### 11.5 Assign a vault item to a folder

```bash
curl -s -X PUT http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"folder_id\": \"$FOLDER_ID\"}" | jq
```

### 11.6 Delete a folder

```bash
curl -s -X DELETE http://localhost:8080/api/v1/vault/folders/$FOLDER_ID \
  -H "Authorization: Bearer $TOKEN" | jq
```

> **What you learned:** Folders are encrypted (name is ciphertext). They support nesting. Items can be moved into folders.

---

## 12. Phase 9 — Trash & Restore

**Goal:** Test soft-delete, trash list, restore, and permanent delete.

### 12.1 Soft delete an item (move to trash)

```bash
curl -s -X DELETE http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** `"Item moved to trash"`

### 12.2 Verify it's gone from the main list

```bash
curl -s http://localhost:8080/api/v1/vault/items \
  -H "Authorization: Bearer $TOKEN" | jq '.data | length'
```

Should be one fewer item.

### 12.3 View trash

```bash
curl -s http://localhost:8080/api/v1/vault/items/trash \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** The deleted item appears here with a `deleted_at` timestamp.

### 12.4 Restore from trash

```bash
curl -s -X POST http://localhost:8080/api/v1/vault/items/$ITEM_ID/restore \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** `"Item restored from trash"`

### 12.5 Verify it's back in the main list

```bash
curl -s http://localhost:8080/api/v1/vault/items \
  -H "Authorization: Bearer $TOKEN" | jq '.data | length'
```

### 12.6 Permanently delete

```bash
# Soft delete first
curl -s -X DELETE http://localhost:8080/api/v1/vault/items/$ITEM_ID \
  -H "Authorization: Bearer $TOKEN" | jq

# Then permanently delete
curl -s -X DELETE http://localhost:8080/api/v1/vault/items/$ITEM_ID/permanent \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** `"Item permanently deleted"`. Item is gone from both list and trash.

> **What you learned:** Soft delete → trash → restore flow works. Permanent delete is irreversible. This prevents accidental data loss.

---

## 13. Phase 10 — Session Management & Logout

**Goal:** Test logout and session revocation.

### 13.1 Login again (to get a fresh token)

(Re-run the login curl from Phase 5 and export TOKEN / REFRESH_TOKEN)

### 13.2 Logout current session

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq
```

**Expected:** `"Logged out successfully"`

### 13.3 Try to refresh with the revoked token

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" | jq
```

**Expected:** HTTP 401 — session was revoked.

### 13.4 Login from multiple "devices", then logout all

```bash
# Login 1
LOGIN1=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@rustvault.dev",
    "master_password_hash": "<your_hash>",
    "device_name": "Device 1"
  }')
TOKEN1=$(echo $LOGIN1 | jq -r '.data.access_token')
REFRESH1=$(echo $LOGIN1 | jq -r '.data.refresh_token')

# Login 2
LOGIN2=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@rustvault.dev",
    "master_password_hash": "<your_hash>",
    "device_name": "Device 2"
  }')
TOKEN2=$(echo $LOGIN2 | jq -r '.data.access_token')
REFRESH2=$(echo $LOGIN2 | jq -r '.data.refresh_token')

# Logout all from device 1
curl -s -X POST http://localhost:8080/api/v1/auth/logout-all \
  -H "Authorization: Bearer $TOKEN1" | jq
```

**Expected:** `"X sessions revoked"`

Then try refreshing from device 2:
```bash
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH2\"}" | jq
```

**Expected:** HTTP 401 — all sessions are revoked.

> **What you learned:** Logout revokes sessions. Logout-all invalidates every session for that user. Refresh token rotation means each token is single-use.

---

## 14. Phase 11 — Error & Edge Case Testing

### 14.1 Invalid JSON body

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d 'this is not json' | jq
```

### 14.2 Missing required fields

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "a@b.com"}' | jq
```

### 14.3 Invalid ObjectId in path

```bash
curl -s http://localhost:8080/api/v1/vault/items/not-a-valid-id \
  -H "Authorization: Bearer $TOKEN" | jq
```

**Expected:** HTTP 422 `"Invalid ID format: not-a-valid-id"`

### 14.4 Expired token (wait 15 min or use a short expiry for testing)

Set `JWT_ACCESS_TOKEN_EXPIRY_SECS=5` in `.env`, restart the server, login, wait 6 seconds, then try a request.

### 14.5 Account lockout (10 failed logins)

```bash
for i in $(seq 1 11); do
  echo "Attempt $i:"
  curl -s -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "email": "test@rustvault.dev",
      "master_password_hash": "d3JvbmdwYXNz"
    }' | jq '.error.code'
done
```

After 10 failures, you should see `ACCOUNT_LOCKED`.

> **Reset the account:** Login with correct credentials after the lockout duration (1 hour by default, or reduce `LOCKOUT_DURATION_SECS` in `.env`).

---

## 15. Phase 12 — Security Header Verification

```bash
curl -sI http://localhost:8080/api/v1/health 2>&1 | grep -iE "^(strict|x-|content-security|referrer|permissions|cache)"
```

**You should see all of these:**

| Header | Expected Value |
|---|---|
| `strict-transport-security` | `max-age=31536000; includeSubDomains; preload` |
| `x-content-type-options` | `nosniff` |
| `x-frame-options` | `DENY` |
| `x-xss-protection` | `1; mode=block` |
| `content-security-policy` | `default-src 'none'; frame-ancestors 'none'` |
| `referrer-policy` | `strict-origin-when-cross-origin` |
| `permissions-policy` | `camera=(), microphone=(), geolocation=()` |
| `cache-control` | `no-store, no-cache, must-revalidate` |

---

## 16. Phase 13 — Database Verification

Use `mongosh` to inspect what the server actually stored.

```bash
docker exec -it rustvault-mongo mongosh rustvault
```

### 16.1 Inspect users

```javascript
db.users.find().pretty()
```

**Verify:**
- `email` is lowercase
- `master_password_hash` starts with `$argon2id$` (PHC format — double-hashed)
- `protected_symmetric_key` is base64 gibberish (encrypted)
- `security_stamp` is a UUID
- **No plaintext password anywhere**

### 16.2 Inspect vault items

```javascript
db.vault_items.find().pretty()
```

**Verify:**
- `name_encrypted` and `data_encrypted` are opaque base64 blobs
- `nonce` is stored per item
- **No plaintext usernames/passwords anywhere**

### 16.3 Inspect sessions

```javascript
db.sessions.find().pretty()
```

**Verify:**
- `refresh_token_hash` is a SHA-256 hex string (NOT the actual token)
- `device_info` includes the IP and user agent
- Revoked sessions have `revoked: true`

### 16.4 Inspect audit logs

```javascript
db.audit_logs.find().sort({timestamp: -1}).pretty()
```

**Verify:**
- Every register, login, failed login, vault CRUD, and logout has a log entry
- Includes IP address and timestamp

### 16.5 Check indexes

```javascript
db.users.getIndexes()
db.vault_items.getIndexes()
db.sessions.getIndexes()
db.audit_logs.getIndexes()
```

---

## 17. Cheat Sheet — All Variables

Keep these in your terminal for quick testing:

```bash
# Generate credentials
python3 scripts/test_crypto_helper.py test@rustvault.dev "MyMasterPassword123!"

# After login, export these (replace with actual values):
export TOKEN="eyJ..."
export REFRESH_TOKEN="eyJ..."
export ITEM_ID="6..."
export FOLDER_ID="6..."

# Quick check: is the server up?
curl -s http://localhost:8080/api/v1/health | jq '.data.status'

# Quick check: am I authenticated?
curl -s http://localhost:8080/api/v1/vault/items -H "Authorization: Bearer $TOKEN" | jq '.success'
```

---

## Testing Order Summary

```
 1. docker compose up -d        ← Start MongoDB
 2. cargo run                   ← Start server
 3. Health checks               ← Server alive?
 4. Tools (password/passphrase) ← Public endpoints work?
 5. Generate test crypto        ← python3 scripts/test_crypto_helper.py
 6. Register                    ← Create account
 7. Register duplicate          ← Conflict handling?
 8. Login                       ← Get JWT tokens
 9. Login wrong password        ← Auth rejection?
10. Token refresh               ← Token rotation works?
11. Create vault items          ← Store encrypted data
12. List / Get vault items      ← Retrieve encrypted data
13. Update vault item           ← Modify data
14. Create folders              ← Organize items
15. Assign item to folder       ← Link them
16. Soft delete → Trash → Restore → Permanent delete
17. Logout / Logout-all         ← Session management
18. Invalid inputs / edge cases ← Error handling
19. Security headers            ← Hardening
20. Database inspection         ← Zero-knowledge verified
```

Each phase builds on the previous one. If something fails, fix it before moving on.
