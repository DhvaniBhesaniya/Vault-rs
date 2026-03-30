
# RustVault — Secure Password Manager

## 1. Application Overview

**RustVault** is a production-grade, self-hosted password manager built with Rust, designed with a **zero-knowledge architecture** — the server never has access to plaintext passwords or the user's master password. All sensitive data is encrypted client-side before reaching the server.

**Tech Stack:**
- **Backend:** Rust (Axum-Web)
- **Database:** MongoDB
- **Future Frontend:** React
- **Deployment:** Docker / Docker Compose

---

## 2. Core Features

| Feature | Description |
|---|---|
| **Vault Management** | Store, retrieve, update, delete encrypted vault items (logins, cards, notes, identities, SSH keys, API keys) |
| **Zero-Knowledge Encryption** | Server stores only encrypted blobs; decryption happens client-side |
| **Master Password Auth** | Single master password protects all vault data via key derivation |
| **Two-Factor Authentication** | TOTP-based 2FA (Google Authenticator / Authy compatible) |
| **RBAC (Role-Based Access)** | Owner, Admin, Member roles for shared organization vaults |
| **Organizations & Sharing** | Securely share credentials within teams using asymmetric encryption |
| **Folders & Categories** | Organize vault items into folders and item types |
| **Password Generator** | Configurable generator (length, symbols, numbers, uppercase, passphrase) |
| **Rate Limiting** | Per-IP and per-user rate limits on auth and API endpoints |
| **Idempotency** | Idempotency keys on all mutation endpoints to prevent duplicate operations |
| **Audit Logging** | Immutable log of every access, modification, login, and admin action |
| **Breach Detection** | k-Anonymity based check against Have I Been Pwned API |
| **Session Management** | JWT access tokens + refresh tokens with device tracking |
| **Import / Export** | Import from Bitwarden/1Password/CSV; Export encrypted backups |

---

## 3. Security Architecture — The Cryptographic Model

This is the most critical section. We follow the same model used by Bitwarden and 1Password, adapted for our stack.

### 3.1 Key Hierarchy

```
Master Password (user input, NEVER stored anywhere)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  Argon2id(master_password, salt=email)              │
│  → Master Key (256-bit)                             │
└─────────────────────────────────────────────────────┘
        │                           │
        ▼                           ▼
┌──────────────────┐    ┌───────────────────────────────┐
│ HKDF-SHA256      │    │ Master Key encrypts:          │
│ → Master Pass    │    │   → Protected Symmetric Key   │
│   Hash           │    │     (AES-256-GCM encrypted)   │
│   (sent to       │    └───────────────────────────────┘
│    server for    │                │
│    auth)         │                ▼
└──────────────────┘    ┌───────────────────────────────┐
        │               │ Symmetric Key (256-bit)       │
        ▼               │ Encrypts all vault items      │
┌──────────────────┐    │ using AES-256-GCM with        │
│ Server hashes    │    │ unique nonce per item         │
│ again with       │    └───────────────────────────────┘
│ Argon2id         │
│ → Stored Hash    │
│   (in DB)        │
└──────────────────┘
```

### 3.2 Algorithms & Parameters

| Purpose | Algorithm | Parameters |
|---|---|---|
| **Key Derivation (Master Key)** | Argon2id | memory=64MB, iterations=3, parallelism=4, output=256-bit |
| **Master Password Hash** | HKDF-SHA256 | Derived from Master Key, info="master_password_hash" |
| **Server-side Password Storage** | Argon2id | memory=64MB, iterations=3 (hashes the hash again) |
| **Vault Item Encryption** | AES-256-GCM | 256-bit key, 96-bit random nonce, 128-bit auth tag |
| **Protected Symmetric Key** | AES-256-GCM | Encrypted by Master Key |
| **Organization Key Exchange** | RSA-OAEP-SHA256 | 4096-bit RSA keypair per user for sharing |
| **TOTP (2FA)** | HMAC-SHA1 | RFC 6238 compliant, 6-digit, 30-second step |
| **JWT Signing** | EdDSA (Ed25519) | Asymmetric signing for stateless token verification |
| **Idempotency Key Hashing** | SHA-256 | For deduplication lookup |
| **CSRF Protection** | HMAC-SHA256 | Double-submit cookie pattern |
| **Breach Check** | SHA-1 + k-Anonymity | Only first 5 chars of hash sent to HIBP API |

### 3.3 Why These Choices?

- **Argon2id** — Winner of the Password Hashing Competition. Resistant to GPU, ASIC, and side-channel attacks. The `id` variant combines resistance to both side-channel (Argon2i) and GPU (Argon2d) attacks.
- **AES-256-GCM** — AEAD cipher providing both confidentiality and integrity. 256-bit key makes brute force infeasible. GCM mode provides authentication, detecting tampering.
- **HKDF** — Standards-based key derivation for deriving multiple keys from a single master key without weakening security.
- **RSA-OAEP** — For asymmetric operations (sharing secrets between users). OAEP padding prevents chosen-ciphertext attacks.
- **Ed25519** — Fast, secure JWT signing with small key sizes.

### 3.4 Zero-Knowledge Flow

```
                    CLIENT                              SERVER
                    ──────                              ──────

REGISTRATION:
  1. User enters email + master_password
  2. master_key = Argon2id(master_password, email)
  3. master_pw_hash = HKDF(master_key, "auth")
  4. symmetric_key = random(256 bits)
  5. protected_sym_key = AES-GCM(master_key, symmetric_key)
  6. rsa_keypair = RSA.generate(4096)
  7. protected_private_key = AES-GCM(symmetric_key, rsa_private_key)
                                              ──────────────►
  8. Send: email, master_pw_hash,            │  9. stored_hash = Argon2id(master_pw_hash)
     protected_sym_key,                      │ 10. Store: email, stored_hash,
     protected_private_key,                  │     protected_sym_key,
     rsa_public_key                          │     protected_private_key, rsa_public_key
                                              ◄──────────────
LOGIN:
  1. User enters email + master_password
  2. master_key = Argon2id(master_password, email)
  3. master_pw_hash = HKDF(master_key, "auth")
                                              ──────────────►
                                             │  4. Verify Argon2id(master_pw_hash, stored_hash)
                                             │  5. If 2FA enabled → require TOTP
                                             │  6. Return JWT + protected_sym_key
                                              ◄──────────────
  7. symmetric_key = AES-GCM.decrypt(master_key, protected_sym_key)
  8. All vault operations use symmetric_key locally

SAVE VAULT ITEM:
  1. plaintext = { username, password, url, notes }
  2. nonce = random(96 bits)
  3. ciphertext = AES-GCM(symmetric_key, nonce, plaintext)
                                              ──────────────►
                                             │  4. Store ciphertext + nonce + tag
                                             │     (server CANNOT read it)
                                              ◄──────────────

RETRIEVE VAULT ITEM:
                                              ──────────────►
                                             │  1. Return ciphertext + nonce + tag
                                              ◄──────────────
  2. plaintext = AES-GCM.decrypt(symmetric_key, nonce, ciphertext)
```

**Key point:** During the API-only phase (no React frontend), the API consumer (curl, Postman, CLI tool) acts as the "client" and must perform the client-side crypto. We will also provide a companion CLI tool in Rust that handles this transparently.

---

## 4. Threat Model & Mitigations

| Threat | Mitigation |
|---|---|
| **Database breach / Server compromise** | All vault data is encrypted with keys the server never possesses. Attacker gets only ciphertext. Master password hashes are double-hashed with Argon2id — extremely expensive to brute force. |
| **Brute force on master password** | Argon2id with high memory cost (64MB per hash). Rate limiting: 5 failed attempts → 15min lockout, exponential backoff. Account lockout after 10 attempts. |
| **Man-in-the-middle** | TLS 1.3 enforced. HSTS headers. Certificate pinning recommended for clients. |
| **Session hijacking** | Short-lived JWT access tokens (15 min). Refresh tokens bound to device fingerprint. Token rotation on refresh. |
| **Replay attacks** | Idempotency keys with TTL. JWT includes `jti` (unique ID) and `iat` (issued at). Nonce in every encryption operation. |
| **Unauthorized access to shared items** | RSA-OAEP encrypted organization keys. Per-item access control. RBAC enforcement at every endpoint. |
| **Insider threat (rogue admin)** | Zero-knowledge: even server admins cannot read vault data. Audit logs are append-only and tamper-evident. |
| **Password reuse / weak passwords** | Configurable master password policy (min length, complexity). Breach detection via HIBP k-Anonymity check on stored passwords. |
| **CSRF attacks** | SameSite cookies + double-submit CSRF token pattern. |
| **XSS (future frontend)** | CSP headers. HttpOnly + Secure cookies. No sensitive data in localStorage (use in-memory only). |
| **Timing attacks** | Constant-time comparison for all hash/token verification. |
| **Memory disclosure (Heartbleed-style)** | Rust's memory safety. Sensitive data in `zeroize`-capable buffers that are wiped on drop. Use `secrecy` crate for `Secret<T>` wrappers. |
| **Denial of Service** | Per-IP rate limiting. Request size limits. Argon2id computation offloaded to background workers to avoid blocking. |

---

## 5. Database Design (MongoDB Collections)

### 5.1 `users`
```json
{
  "_id": "ObjectId",
  "email": "user@example.com",          // unique, indexed
  "name": "John Doe",
  "master_password_hash": "base64...",   // Argon2id(HKDF(master_key))
  "protected_symmetric_key": "base64...", // AES-GCM encrypted by master key
  "protected_private_key": "base64...",  // AES-GCM encrypted by symmetric key
  "public_key": "base64...",             // RSA-4096 public key (plaintext)
  "kdf_params": {
    "algorithm": "argon2id",
    "memory_kb": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "two_factor": {
    "enabled": false,
    "totp_secret_encrypted": null,       // encrypted with symmetric key
    "recovery_codes_encrypted": null
  },
  "security_stamp": "uuid-v4",          // rotated on password change, invalidates all sessions
  "account_status": "active",           // active | locked | suspended
  "failed_login_attempts": 0,
  "locked_until": null,
  "password_hint": "optional hint",
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

### 5.2 `vault_items`
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",                // indexed
  "organization_id": null,              // null for personal items
  "folder_id": null,                    // optional folder reference
  "item_type": "login",                 // login | card | identity | secure_note | ssh_key | api_credential
  "name_encrypted": "base64...",        // AES-GCM encrypted item name
  "data_encrypted": "base64...",        // AES-GCM encrypted JSON blob (all sensitive fields)
  "nonce": "base64...",                 // 96-bit nonce used for encryption
  "favorite": false,
  "reprompt": false,                    // require master password re-entry to view
  "tags": ["work", "cloud"],            // plaintext tags (optional, for search)
  "created_at": "ISODate",
  "updated_at": "ISODate",
  "deleted_at": null                    // soft delete for trash/recovery
}
```

**Encrypted `data` payload by type:**

**Login:**
```json
{
  "username": "admin",
  "password": "s3cur3P@ss!",
  "totp_seed": "JBSWY3DPEHPK3PXP",
  "uris": [{"uri": "https://example.com", "match_type": "domain"}],
  "notes": "Corporate login",
  "custom_fields": [
    {"name": "Security Q", "value": "Answer", "type": "hidden"}
  ]
}
```

**Card:**
```json
{
  "cardholder_name": "John Doe",
  "number": "4111111111111111",
  "exp_month": "12",
  "exp_year": "2028",
  "cvv": "123",
  "brand": "visa"
}
```

**Identity:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "address": { "street": "...", "city": "...", "state": "...", "zip": "...", "country": "..." },
  "ssn": "123-45-6789",
  "passport_number": "..."
}
```

**Secure Note:**
```json
{
  "content": "Free-form encrypted text"
}
```

**SSH Key:**
```json
{
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----...",
  "public_key": "ssh-ed25519 AAAA...",
  "fingerprint": "SHA256:...",
  "passphrase": "optional"
}
```

**API Credential:**
```json
{
  "api_key": "sk_live_...",
  "api_secret": "...",
  "endpoint": "https://api.example.com",
  "auth_type": "bearer",
  "notes": "Production API key"
}
```

### 5.3 `folders`
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "name_encrypted": "base64...",
  "parent_folder_id": null,
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

### 5.4 `organizations`
```json
{
  "_id": "ObjectId",
  "name": "Acme Corp",
  "owner_user_id": "ObjectId",
  "billing_email": "billing@acme.com",
  "org_symmetric_key_encrypted": "base64...", // encrypted per-member with their RSA public key
  "created_at": "ISODate",
  "updated_at": "ISODate"
}
```

### 5.5 `org_members`
```json
{
  "_id": "ObjectId",
  "organization_id": "ObjectId",
  "user_id": "ObjectId",
  "role": "admin",                          // owner | admin | member | viewer
  "org_key_encrypted": "base64...",         // org symmetric key encrypted with user's RSA public key
  "status": "confirmed",                   // invited | confirmed | revoked
  "permissions": {
    "manage_members": true,
    "manage_collections": true,
    "manage_policies": false,
    "export_vault": false
  },
  "invited_at": "ISODate",
  "confirmed_at": "ISODate"
}
```

### 5.6 `collections` (shared folders within orgs)
```json
{
  "_id": "ObjectId",
  "organization_id": "ObjectId",
  "name_encrypted": "base64...",
  "assigned_members": [
    { "user_id": "ObjectId", "read_only": false }
  ],
  "created_at": "ISODate"
}
```

### 5.7 `sessions`
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "refresh_token_hash": "sha256...",
  "device_info": {
    "name": "Chrome on Linux",
    "ip": "192.168.1.1",
    "user_agent": "..."
  },
  "created_at": "ISODate",
  "expires_at": "ISODate",
  "last_used_at": "ISODate",
  "revoked": false
}
```

### 5.8 `audit_logs`
```json
{
  "_id": "ObjectId",
  "user_id": "ObjectId",
  "organization_id": null,
  "action": "vault_item.read",             // auth.login | auth.logout | auth.failed_login |
                                            // vault_item.create | vault_item.read | vault_item.update |
                                            // vault_item.delete | password.changed | 2fa.enabled |
                                            // org.member_added | org.member_removed | export.requested
  "resource_type": "vault_item",
  "resource_id": "ObjectId",
  "ip_address": "192.168.1.1",
  "user_agent": "...",
  "metadata": {},                           // action-specific details
  "timestamp": "ISODate"
}
```

### 5.9 `idempotency_keys`
```json
{
  "_id": "ObjectId",
  "key_hash": "sha256...",                  // indexed, unique
  "user_id": "ObjectId",
  "endpoint": "POST /api/v1/vault/items",
  "response_status": 201,
  "response_body_encrypted": "base64...",
  "created_at": "ISODate",
  "expires_at": "ISODate"                   // TTL index, auto-delete after 24h
}
```

### 5.10 `rate_limit_counters`
```json
{
  "_id": "ObjectId",
  "key": "ip:192.168.1.1:login",           // ip:{ip}:{action} or user:{id}:{action}
  "count": 3,
  "window_start": "ISODate",
  "expires_at": "ISODate"                   // TTL index
}
```

### 5.11 MongoDB Indexes

```javascript
// users
db.users.createIndex({ "email": 1 }, { unique: true })
db.users.createIndex({ "security_stamp": 1 })

// vault_items
db.vault_items.createIndex({ "user_id": 1, "deleted_at": 1 })
db.vault_items.createIndex({ "organization_id": 1 })
db.vault_items.createIndex({ "folder_id": 1 })
db.vault_items.createIndex({ "user_id": 1, "item_type": 1 })

// sessions
db.sessions.createIndex({ "user_id": 1 })
db.sessions.createIndex({ "refresh_token_hash": 1 }, { unique: true })
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })

// audit_logs
db.audit_logs.createIndex({ "user_id": 1, "timestamp": -1 })
db.audit_logs.createIndex({ "organization_id": 1, "timestamp": -1 })
db.audit_logs.createIndex({ "timestamp": 1 }, { expireAfterSeconds: 7776000 }) // 90 days

// idempotency_keys
db.idempotency_keys.createIndex({ "key_hash": 1, "user_id": 1 }, { unique: true })
db.idempotency_keys.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })

// rate_limit_counters
db.rate_limit_counters.createIndex({ "key": 1 }, { unique: true })
db.rate_limit_counters.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })
```

---

## 6. API Design (REST)

### 6.1 Authentication

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Register new account | 3/hour/IP |
| POST | `/api/v1/auth/login` | Login (returns JWT + protected keys) | 5/15min/IP |
| POST | `/api/v1/auth/login/2fa` | Complete login with TOTP code | 5/15min/IP |
| POST | `/api/v1/auth/refresh` | Refresh access token | 10/min/user |
| POST | `/api/v1/auth/logout` | Revoke current session | 10/min/user |
| POST | `/api/v1/auth/logout-all` | Revoke all sessions | 3/hour/user |

### 6.2 Account Management

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| GET | `/api/v1/account/profile` | Get account profile | 30/min |
| PUT | `/api/v1/account/profile` | Update profile | 10/min |
| POST | `/api/v1/account/change-password` | Change master password (re-encrypts all keys) | 3/hour |
| POST | `/api/v1/account/delete` | Delete account permanently | 1/day |
| GET | `/api/v1/account/sessions` | List active sessions | 10/min |
| DELETE | `/api/v1/account/sessions/{id}` | Revoke a specific session | 10/min |

### 6.3 Two-Factor Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/account/2fa/setup` | Generate TOTP secret + QR data |
| POST | `/api/v1/account/2fa/enable` | Verify TOTP code and enable 2FA |
| POST | `/api/v1/account/2fa/disable` | Disable 2FA (requires master password) |
| GET | `/api/v1/account/2fa/recovery-codes` | Get encrypted recovery codes |
| POST | `/api/v1/account/2fa/recovery-codes/regenerate` | Regenerate recovery codes |

### 6.4 Vault Items

| Method | Endpoint | Description | Idempotent |
|---|---|---|---|
| GET | `/api/v1/vault/items` | List all vault items (encrypted) | — |
| GET | `/api/v1/vault/items/{id}` | Get single vault item | — |
| POST | `/api/v1/vault/items` | Create vault item | ✅ |
| PUT | `/api/v1/vault/items/{id}` | Update vault item | ✅ |
| DELETE | `/api/v1/vault/items/{id}` | Soft delete (move to trash) | ✅ |
| POST | `/api/v1/vault/items/{id}/restore` | Restore from trash | ✅ |
| DELETE | `/api/v1/vault/items/{id}/permanent` | Permanent delete | ✅ |
| GET | `/api/v1/vault/items/trash` | List trashed items | — |

### 6.5 Folders

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/vault/folders` | List folders |
| POST | `/api/v1/vault/folders` | Create folder |
| PUT | `/api/v1/vault/folders/{id}` | Rename folder |
| DELETE | `/api/v1/vault/folders/{id}` | Delete folder |

### 6.6 Password Tools

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/tools/generate-password` | Generate random password |
| POST | `/api/v1/tools/generate-passphrase` | Generate random passphrase |
| POST | `/api/v1/tools/check-strength` | Check password strength |
| POST | `/api/v1/tools/check-breach` | Check if password is in known breaches (k-Anonymity) |

### 6.7 Organizations

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/organizations` | List user's organizations |
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations/{id}` | Get organization details |
| PUT | `/api/v1/organizations/{id}` | Update organization |
| DELETE | `/api/v1/organizations/{id}` | Delete organization |
| GET | `/api/v1/organizations/{id}/members` | List members |
| POST | `/api/v1/organizations/{id}/members/invite` | Invite member |
| PUT | `/api/v1/organizations/{id}/members/{uid}` | Update member role |
| DELETE | `/api/v1/organizations/{id}/members/{uid}` | Remove member |
| GET | `/api/v1/organizations/{id}/collections` | List collections |
| POST | `/api/v1/organizations/{id}/collections` | Create collection |
| GET | `/api/v1/organizations/{id}/vault/items` | List org vault items |
| POST | `/api/v1/organizations/{id}/vault/items` | Create org vault item |

### 6.8 Audit & Admin

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/audit/logs` | Get audit logs (paginated) |
| GET | `/api/v1/organizations/{id}/audit/logs` | Get org audit logs |

### 6.9 Import / Export

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/vault/import` | Import vault data (Bitwarden/1Password/CSV) |
| POST | `/api/v1/vault/export` | Export encrypted vault backup |

### 6.10 Health & Meta

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness check (DB connectivity) |

---

## 7. Request/Response Standards

### 7.1 Headers

```
Authorization: Bearer <jwt_access_token>
Content-Type: application/json
X-Idempotency-Key: <uuid-v4>           // required on POST/PUT/DELETE mutations
X-Request-ID: <uuid-v4>                // for request tracing
X-Device-Type: cli|web|mobile          // client device identification
```

### 7.2 Standard Response Envelope

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "uuid",
    "timestamp": "ISO-8601",
    "pagination": {
      "page": 1,
      "per_page": 50,
      "total": 243,
      "total_pages": 5
    }
  }
}
```

### 7.3 Error Response

```json
{
  "success": false,
  "error": {
    "code": "VAULT_ITEM_NOT_FOUND",
    "message": "The requested vault item does not exist.",
    "details": null
  },
  "meta": {
    "request_id": "uuid",
    "timestamp": "ISO-8601"
  }
}
```

---

## 8. RBAC Model

### 8.1 Roles & Permissions Matrix

| Permission | Owner | Admin | Member | Viewer |
|---|---|---|---|---|
| Manage organization settings | ✅ | ❌ | ❌ | ❌ |
| Delete organization | ✅ | ❌ | ❌ | ❌ |
| Manage members (invite/remove) | ✅ | ✅ | ❌ | ❌ |
| Assign roles | ✅ | ✅* | ❌ | ❌ |
| Create collections | ✅ | ✅ | ❌ | ❌ |
| Manage collection assignments | ✅ | ✅ | ❌ | ❌ |
| Create org vault items | ✅ | ✅ | ✅ | ❌ |
| Edit org vault items | ✅ | ✅ | ✅** | ❌ |
| View org vault items | ✅ | ✅ | ✅ | ✅ |
| Delete org vault items | ✅ | ✅ | ❌ | ❌ |
| View audit logs | ✅ | ✅ | ❌ | ❌ |
| Export org vault | ✅ | ❌ | ❌ | ❌ |

_*Admins cannot assign Owner role._
_**Members can only edit items they created._

### 8.2 Personal Vault

Personal vault items have no RBAC — they are fully owned by the user. Only the user can access them.

---

## 9. Rate Limiting Strategy

### 9.1 Tiers

| Tier | Scope | Endpoints | Limit |
|---|---|---|---|
| **Auth (strict)** | Per IP | `/auth/login`, `/auth/register` | 5 requests / 15 min |
| **Auth 2FA** | Per IP | `/auth/login/2fa` | 5 requests / 15 min |
| **Sensitive** | Per User | `/account/change-password`, `/account/delete` | 3 requests / hour |
| **Write** | Per User | All POST/PUT/DELETE | 60 requests / min |
| **Read** | Per User | All GET | 120 requests / min |
| **Tools** | Per IP | `/tools/*` | 30 requests / min |

### 9.2 Implementation

- **Algorithm:** Sliding window counter (stored in MongoDB with TTL indexes)
- **Headers returned:** `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- **On limit exceeded:** HTTP 429 with `Retry-After` header
- **Account lockout:** After 10 consecutive failed logins → account locked for 1 hour

---

## 10. Idempotency Strategy

### 10.1 How It Works

1. Client sends `X-Idempotency-Key: <uuid>` header with every mutation request
2. Server computes `SHA-256(user_id + idempotency_key + endpoint)`
3. Checks MongoDB `idempotency_keys` collection:
   - **Key exists:** Return stored response (replay)
   - **Key absent:** Process request, store response with 24-hour TTL
4. Keys auto-expire via MongoDB TTL index after 24 hours

### 10.2 Protected Endpoints

All `POST`, `PUT`, `DELETE` endpoints require `X-Idempotency-Key` header. Requests without it receive `400 Bad Request`.

---

## 11. Rust Project Structure

```
rustvault/
├── Cargo.toml
├── Cargo.lock
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── README.md
├── DESIGN.md
├── config/
│   ├── default.toml
│   ├── development.toml
│   ├── production.toml
│   └── test.toml
├── migrations/                     # MongoDB index setup scripts
│   └── 001_create_indexes.js
├── src/
│   ├── main.rs                     # Entry point, server bootstrap
│   ├── lib.rs                      # Library root (re-exports)
│   ├── config/
│   │   ├── mod.rs
│   │   └── settings.rs             # Config loading (config crate)
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── argon2.rs               # Argon2id hashing
│   │   ├── aes_gcm.rs              # AES-256-GCM encrypt/decrypt
│   │   ├── hkdf.rs                 # HKDF key derivation
│   │   ├── rsa.rs                  # RSA-OAEP operations
│   │   └── password_generator.rs   # Password & passphrase generation
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── vault_item.rs
│   │   ├── folder.rs
│   │   ├── organization.rs
│   │   ├── org_member.rs
│   │   ├── collection.rs
│   │   ├── session.rs
│   │   ├── audit_log.rs
│   │   └── idempotency.rs
│   ├── repositories/               # Data access layer (MongoDB)
│   │   ├── mod.rs
│   │   ├── user_repo.rs
│   │   ├── vault_item_repo.rs
│   │   ├── folder_repo.rs
│   │   ├── organization_repo.rs
│   │   ├── session_repo.rs
│   │   ├── audit_log_repo.rs
│   │   └── idempotency_repo.rs
│   ├── services/                   # Business logic
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── vault_service.rs
│   │   ├── folder_service.rs
│   │   ├── organization_service.rs
│   │   ├── audit_service.rs
│   │   ├── totp_service.rs
│   │   ├── breach_check_service.rs
│   │   └── import_export_service.rs
│   ├── handlers/                   # HTTP request handlers (Axum-Web)
│   │   ├── mod.rs
│   │   ├── auth_handler.rs
│   │   ├── account_handler.rs
│   │   ├── vault_handler.rs
│   │   ├── folder_handler.rs
│   │   ├── organization_handler.rs
│   │   ├── tools_handler.rs
│   │   ├── audit_handler.rs
│   │   └── health_handler.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs                 # JWT extraction & validation
│   │   ├── rate_limiter.rs         # Rate limiting middleware
│   │   ├── idempotency.rs          # Idempotency key middleware
│   │   ├── request_id.rs           # X-Request-ID injection
│   │   ├── security_headers.rs     # HSTS, CSP, X-Frame-Options, etc.
│   │   └── audit.rs                # Automatic audit logging
│   ├── errors/
│   │   ├── mod.rs
│   │   └── app_error.rs            # Unified error type + Axum responder
│   ├── dto/                        # Data Transfer Objects (request/response)
│   │   ├── mod.rs
│   │   ├── auth_dto.rs
│   │   ├── vault_dto.rs
│   │   ├── folder_dto.rs
│   │   ├── organization_dto.rs
│   │   └── common_dto.rs
│   └── utils/
│       ├── mod.rs
│       ├── jwt.rs                  # JWT creation & verification (Ed25519)
│       ├── totp.rs                 # TOTP generation & verification
│       ├── validation.rs           # Input validation helpers
│       └── zeroize_helpers.rs      # Memory cleanup utilities
└── tests/
    ├── integration/
    │   ├── auth_tests.rs
    │   ├── vault_tests.rs
    │   └── organization_tests.rs
    └── unit/
        ├── crypto_tests.rs
        └── service_tests.rs
```

---

## 12. Key Rust Crates

| Crate | Purpose |
|---|---|
| `Axum-web` | HTTP framework |
| `mongodb` | MongoDB async driver |
| `serde` / `serde_json` | Serialization |
| `argon2` | Argon2id password hashing |
| `aes-gcm` | AES-256-GCM encryption |
| `hkdf` + `sha2` | HKDF key derivation |
| `rsa` | RSA-OAEP operations |
| `ed25519-dalek` | Ed25519 for JWT signing |
| `jsonwebtoken` | JWT encode/decode |
| `totp-rs` | TOTP 2FA |
| `uuid` | UUID generation |
| `chrono` | Date/time handling |
| `tracing` + `tracing-subscriber` | Structured logging |
| `config` | Configuration management |
| `validator` | Input validation with derive macros |
| `secrecy` | `Secret<T>` wrapper (auto-redact in logs) |
| `zeroize` | Zero memory on drop for sensitive data |
| `rand` / `rand_chacha` | Cryptographically secure random |
| `reqwest` | HTTP client (for HIBP API) |
| `base64` | Base64 encoding |
| `thiserror` | Error type derivation |
| `tokio` | Async runtime |
| `dotenv` | Environment variable loading |

---

## 13. Security Hardening Checklist

- [ ] All sensitive fields wrapped in `Secret<T>` from `secrecy` crate
- [ ] All crypto buffers implement `Zeroize` + `ZeroizeOnDrop`
- [ ] Constant-time comparison for all hash verifications
- [ ] No plaintext secrets in logs (tracing filters)
- [ ] TLS termination enforced (reverse proxy or native)
- [ ] HSTS, X-Content-Type-Options, X-Frame-Options, CSP headers
- [ ] Request body size limit (1MB default)
- [ ] JWT access token lifetime: 15 minutes
- [ ] Refresh token lifetime: 7 days (configurable)
- [ ] Refresh token rotation (old token invalidated on use)
- [ ] Security stamp validation on every authenticated request
- [ ] Account lockout after repeated failed attempts
- [ ] Argon2id with ≥64MB memory cost
- [ ] Unique random nonce for every AES-GCM encryption
- [ ] Audit log for every sensitive operation
- [ ] MongoDB connections use TLS + SCRAM-SHA-256 auth
- [ ] No sensitive data in URL query parameters
- [ ] Input validation on all endpoints (length, format, type)
- [ ] Soft delete with 30-day retention before permanent purge

---

## 14. Development Phases

### Phase 1 — Core Backend (Current)
- [x] Design document
- [ ] Project setup (Cargo, config, Docker Compose with MongoDB)
- [ ] Crypto module (Argon2id, AES-256-GCM, HKDF)
- [ ] User registration & login
- [ ] JWT authentication middleware
- [ ] Vault CRUD (create, read, update, soft-delete)
- [ ] Folders
- [ ] Rate limiting middleware
- [ ] Idempotency middleware
- [ ] Audit logging
- [ ] Health endpoints
- [ ] Password generator
- [ ] Integration tests

### Phase 2 — Advanced Features
- [ ] TOTP 2FA
- [ ] Breach detection (HIBP)
- [ ] Organizations & RBAC
- [ ] Shared collections
- [ ] Import/Export
- [ ] CLI companion tool

### Phase 3 — React Frontend
- [ ] Login / Register UI
- [ ] Vault browser
- [ ] Client-side crypto (WebCrypto API)
- [ ] Password generator UI
- [ ] Organization management
- [ ] 2FA setup flow

---

## 15. How Password Security Compares

| Feature | RustVault | Bitwarden | 1Password |
|---|---|---|---|
| Zero-knowledge | ✅ | ✅ | ✅ |
| KDF | Argon2id | Argon2id / PBKDF2 | Argon2id |
| Vault encryption | AES-256-GCM | AES-256-CBC + HMAC | AES-256-GCM |
| Key exchange (sharing) | RSA-4096 OAEP | RSA-2048 OAEP | SRP + AES |
| Open source | ✅ | ✅ (server) | ❌ |
| Self-hosted | ✅ | ✅ | ❌ |
| Language | Rust | C# / TypeScript | Go / TypeScript |
| Memory safety | ✅ (Rust) | Managed (CLR) | ✅ (Go) |

---

*This document serves as the single source of truth for RustVault's architecture and security model. All implementation should conform to the specifications outlined here.*
