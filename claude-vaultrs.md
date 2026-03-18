# VaultRS — Production-Grade Password Manager
## Application Design Document (Backend v1.0)
### Stack: Rust · Axum · MongoDB · Redis

---

## 1. Executive Summary

VaultRS is a zero-knowledge, end-to-end encrypted password manager built in Rust. The system stores every secret in an encrypted form that only the authenticated user can decrypt — the server never has access to plaintext credentials at any point in the request lifecycle. The backend exposes a RESTful API designed for a React frontend to be added in a future phase.

The design is modelled on the threat model of Bitwarden and 1Password, but built from scratch in Rust to achieve memory safety, maximum performance, and minimal attack surface.

---

## 2. Application Description

### What is VaultRS?

VaultRS is a personal and team password management system that:

- Stores encrypted credentials, API keys, SSH keys, secure notes, credit cards, software licenses, and any other sensitive secret.
- Organises secrets into user-defined Collections (folders/categories) and Tags.
- Supports Role-Based Access Control (RBAC) for sharing secrets within a team context.
- Enforces rate limiting and idempotency on all write operations.
- Provides a full audit trail of every access and mutation.
- Integrates Two-Factor Authentication (TOTP/WebAuthn) as a first-class feature.

### Who is it for?

Phase 1 target: a single personal user (the developer themselves) operating through the REST API, later served by a React SPA.

---

## 3. Core Architecture

```
Client (React SPA / curl / mobile)
         │
         ▼
    ┌─────────────────────────────┐
    │     Axum HTTP Server        │   ← Rust, async, Tower middleware
    │   (TLS termination at LB)   │
    └────────────┬────────────────┘
                 │
       ┌─────────▼──────────┐
       │   Middleware Stack  │
       │  ┌──────────────┐  │
       │  │ Rate Limiter │  │   ← Redis-backed, sliding window
       │  ├──────────────┤  │
       │  │ Auth (JWT)   │  │   ← RS256 access + refresh tokens
       │  ├──────────────┤  │
       │  │ Idempotency  │  │   ← Key checked before handlers
       │  ├──────────────┤  │
       │  │ Audit Logger │  │   ← Async, non-blocking
       │  └──────────────┘  │
       └─────────┬──────────┘
                 │
    ┌────────────▼────────────────┐
    │       Route Handlers        │
    │  /auth  /vault  /items      │
    │  /collections  /audit       │
    │  /admin  /health            │
    └────────────┬────────────────┘
                 │
    ┌────────────▼────────────────┐
    │       Service Layer         │
    │  (business logic, crypto)   │
    └──────────┬──────────────────┘
               │
    ┌──────────┴──────────────────┐
    │    Repository Layer         │
    │   (MongoDB via mongodb-rs)  │
    └──────────┬──────────────────┘
               │
    ┌──────────▼──────────────────┐
    │         MongoDB             │
    │  (Atlas or self-hosted)     │
    └─────────────────────────────┘

    Redis (rate limiting + idempotency + session revocation)
    S3 / local FS (encrypted attachment blobs, optional)
```

---

## 4. Resource Catalogue

Every resource below is a MongoDB collection.

### 4.1 Users (`users`)

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | Primary key |
| `public_id` | UUIDv4 | Exposed in API responses |
| `email` | String | Unique, lowercase, indexed |
| `email_verified` | bool | Must be true to use vault |
| `master_password_hash` | String | Argon2id hash of stretched master key |
| `master_key_hint` | String? | Optional plaintext hint |
| `protected_symmetric_key` | String | AES-256-GCM encrypted vault key, base64 |
| `protected_private_key` | String | Encrypted RSA private key for sharing |
| `public_key` | String | RSA public key, unencrypted |
| `kdf_algorithm` | Enum | `argon2id` |
| `kdf_iterations` | u32 | Min 3, recommended 4 |
| `kdf_memory` | u32 | In KB, min 65536 |
| `kdf_parallelism` | u32 | Min 1 |
| `kdf_salt` | String | 128-bit random, base64 |
| `two_factor_enabled` | bool | — |
| `totp_secret` | String? | Encrypted with vault key |
| `webauthn_credentials` | Vec | FIDO2 authenticators |
| `security_stamp` | String | UUID, rotated on password change |
| `failed_login_attempts` | u32 | Reset on success |
| `locked_until` | DateTime? | Account lockout expiry |
| `roles` | Vec\<Role\> | System-level roles |
| `created_at` | DateTime | — |
| `updated_at` | DateTime | — |
| `last_login_at` | DateTime? | — |
| `deleted_at` | DateTime? | Soft delete |

### 4.2 Vault Items (`vault_items`)

The fundamental secret store. All sensitive fields are encrypted client-side before storage.

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `public_id` | UUIDv4 | — |
| `user_id` | ObjectId | Owner reference |
| `organization_id` | ObjectId? | If shared |
| `collection_ids` | Vec\<ObjectId\> | Categories/folders |
| `type` | ItemType enum | See below |
| `name` | String | Encrypted |
| `notes` | String? | Encrypted |
| `fields` | Vec\<CustomField\> | Encrypted |
| `encrypted_data` | String | AES-256-GCM ciphertext (base64) |
| `favourite` | bool | — |
| `tags` | Vec\<String\> | Encrypted |
| `reprompt` | bool | Ask master password again to view |
| `revision_date` | DateTime | Last changed |
| `password_changed_at` | DateTime? | For age warnings |
| `created_at` | DateTime | — |
| `updated_at` | DateTime | — |
| `deleted_at` | DateTime? | Soft delete (trash) |

**ItemType Enum** (stored encrypted in `encrypted_data`):
- `Login` — URL, username, password, TOTP seed, URIs, autofill match rule
- `SecureNote` — arbitrary encrypted text
- `CreditCard` — card number, CVV, expiry, holder name, billing address
- `Identity` — name, address, passport, driving licence, SSN
- `SSHKey` — private key (encrypted), public key, passphrase
- `ApiKey` — key value, service name, scope, expiry
- `SoftwareLicense` — license key, product, quantity, expiry
- `DatabaseCredential` — host, port, db name, username, password, connection string
- `WifiPassword` — SSID, password, encryption type
- `BankAccount` — account number, routing number, IBAN, BIC

### 4.3 Collections (`collections`)

Organisational folders/categories.

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `public_id` | UUIDv4 | — |
| `user_id` | ObjectId | Owner |
| `organization_id` | ObjectId? | — |
| `name` | String | Encrypted |
| `external_id` | String? | For directory sync |
| `hide_passwords` | bool | Members see only metadata |
| `read_only` | bool | Members cannot write |
| `created_at` | DateTime | — |
| `updated_at` | DateTime | — |

### 4.4 Organizations (`organizations`)

Group/team context for shared vaults.

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `public_id` | UUIDv4 | — |
| `name` | String | — |
| `plan` | Plan enum | `free`, `teams`, `enterprise` |
| `max_users` | u32 | Plan limit |
| `two_factor_required` | bool | Enforce 2FA for members |
| `billing_email` | String | — |
| `created_at` | DateTime | — |

### 4.5 Organization Members (`org_members`)

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `organization_id` | ObjectId | — |
| `user_id` | ObjectId | — |
| `role` | OrgRole enum | `owner`, `admin`, `manager`, `member`, `custom` |
| `collections` | Vec\<CollectionAccess\> | Granular per-collection overrides |
| `status` | MemberStatus | `invited`, `accepted`, `confirmed`, `revoked` |
| `protected_symmetric_key` | String | Org vault key, encrypted with user's public key |
| `invited_at` | DateTime | — |
| `confirmed_at` | DateTime? | — |

### 4.6 Refresh Tokens (`refresh_tokens`)

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `user_id` | ObjectId | — |
| `token_hash` | String | SHA-256 of the opaque token |
| `family_id` | UUIDv4 | Detect refresh token rotation attacks |
| `device_id` | String | Fingerprint |
| `ip_address` | String | Creation IP |
| `user_agent` | String | — |
| `expires_at` | DateTime | TTL index on this field |
| `revoked_at` | DateTime? | — |
| `created_at` | DateTime | — |

### 4.7 Audit Log (`audit_logs`)

Immutable. Never updated, never deleted.

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `actor_user_id` | ObjectId? | Null for system events |
| `organization_id` | ObjectId? | — |
| `event_type` | AuditEvent enum | See below |
| `target_type` | String | Resource type string |
| `target_id` | String | Resource public_id |
| `ip_address` | String | — |
| `user_agent` | String | — |
| `idempotency_key` | String? | — |
| `metadata` | BSON doc | Extra context, non-sensitive |
| `created_at` | DateTime | TTL index: 90 days default |

**AuditEvent variants**: `UserLogin`, `UserLoginFailed`, `UserLogout`, `UserPasswordChanged`, `UserTwoFactorEnabled`, `UserTwoFactorDisabled`, `VaultItemCreated`, `VaultItemViewed`, `VaultItemUpdated`, `VaultItemDeleted`, `VaultItemRestored`, `CollectionCreated`, `CollectionUpdated`, `OrgMemberInvited`, `OrgMemberConfirmed`, `OrgMemberRevoked`, `ApiKeyUsed`, `EmergencyAccessGranted`, etc.

### 4.8 Idempotency Records (`idempotency_records`)

| Field | Type | Notes |
|---|---|---|
| `_id` | String | The idempotency key itself |
| `user_id` | ObjectId | — |
| `method` | String | HTTP method |
| `path` | String | Normalized URL path |
| `status_code` | u16 | Stored response code |
| `response_body` | String | Stored response body |
| `created_at` | DateTime | TTL: 24 hours |

### 4.9 Emergency Access (`emergency_access`)

Allow a trusted contact to access your vault if you're incapacitated.

| Field | Type | Notes |
|---|---|---|
| `_id` | ObjectId | — |
| `grantor_user_id` | ObjectId | Who grants access |
| `grantee_user_id` | ObjectId | Who receives access |
| `type` | EmergencyType | `view`, `takeover` |
| `status` | EmergencyStatus | `invited`, `accepted`, `recovery_initiated`, `recovery_approved` |
| `wait_time_days` | u32 | Grantor has this many days to reject |
| `key_encrypted` | String? | Set when approved, grantor's vault key encrypted with grantee public key |
| `recovery_initiated_at` | DateTime? | — |
| `created_at` | DateTime | — |

---

## 5. Security Architecture

This is the most critical section. Every design decision flows from one principle:

> **The server must NEVER be able to decrypt user vault data, even if the entire database is exfiltrated.**

### 5.1 Zero-Knowledge Architecture

```
User's brain
    │
    │  Master Password (never transmitted)
    ▼
[Client-side only] ──────────────────────────────────────────────
│                                                                │
│  Step 1: PBKDF — Argon2id                                     │
│  Input:  master_password + email (lowercased)                 │
│  Params: iterations=4, memory=65536 KB, parallelism=4         │
│  Output: 256-bit Master Key (MK)                              │
│                                                               │
│  Step 2: HKDF-SHA256 split                                    │
│  MK ──► HKDF(info="enc") ──► Encryption Key (EK, 256-bit)    │
│  MK ──► HKDF(info="mac") ──► MAC Key (MACk, 256-bit)        │
│                                                               │
│  Step 3: Master Password Hash for Server Auth                 │
│  Input:  MK + master_password                                 │
│  Output: MPH = PBKDF2(MK, master_password, 1 iter)           │
│  This is the ONLY thing sent to the server.                   │
│                                                               │
│  Step 4: Protected Symmetric Key                              │
│  Server returns: PSK (a 512-bit random vault key,             │
│  AES-256-GCM encrypted with EK, stored server-side)          │
│  Client decrypts PSK using EK → Vault Key (VK)               │
│                                                               │
│  Step 5: Vault Item encryption                                │
│  Each item encrypted: AES-256-GCM(VK, plaintext) → ciphertext│
│  IV is 96-bit random, prepended to ciphertext                 │
│  Auth tag (128-bit) is verified on decryption                 │
│                                                               │
└─────────────────────────────────────────────────────────────-──
    │
    │  Only sends: { email, MPH, encrypted_item_ciphertext }
    ▼
[Server] — stores only ciphertext, can verify identity, CANNOT decrypt
```

### 5.2 Key Derivation Parameters

| KDF | Algorithm | Parameters |
|---|---|---|
| Master Key | Argon2id | `m=65536`, `t=4`, `p=4`, `salt=128-bit-random`, `output=256-bit` |
| Server Hash | Argon2id | `m=65536`, `t=3`, `p=4` (applied server-side to MPH) |
| Stretch for auth | HKDF-SHA256 | Split into EK + MACk |
| Vault Key wrap | AES-256-GCM | 96-bit IV, 128-bit tag |
| Item encryption | AES-256-GCM | 96-bit IV, 128-bit tag, key = VK |
| Sharing | RSA-OAEP-SHA256 | 4096-bit keys per user |

**Why Argon2id?** It is the winner of the Password Hashing Competition (2015). It is memory-hard (resists GPU/ASIC attacks), time-hard (resists cheap iteration attacks), and data-independent (resists timing side-channels). It is the OWASP recommended algorithm as of 2024.

**Why NOT bcrypt/scrypt?** bcrypt is limited to 72 bytes of input and has a fixed memory footprint. scrypt is vulnerable to time-memory trade-off attacks. Argon2id combines the best properties of both.

**Why NOT SHA-256 for passwords?** SHA-256 is not a password hash. It has no salt, no memory-hardness, and billions of hashes per second are achievable on commodity GPUs, making brute force trivial.

### 5.3 Item Encryption in Detail

```
AES-256-GCM encryption of a vault item:

Input:
  plaintext = JSON serialised item data
  key       = Vault Key (256-bit, derived above)

Process:
  iv          = CSPRNG(96 bits)                  ← from OS entropy
  (ciphertext, tag) = AES-256-GCM(key, iv, plaintext, aad)
  aad         = item.public_id + "|" + item.user_id   ← authenticated additional data

Stored as:
  "$aes256gcm$" + base64(iv + ciphertext + tag)

Decryption:
  parse version prefix
  split iv (12 bytes) + ciphertext + tag (16 bytes)
  verify tag using aad before returning plaintext
  abort on any tag mismatch (do NOT return partial data)
```

The use of AAD (Additional Authenticated Data) ensures that ciphertext cannot be moved between users or items by an attacker with database access. If they copy the ciphertext blob to a different item record, the AAD check fails.

### 5.4 Transport Security

- TLS 1.3 minimum, TLS 1.2 with approved cipher suites only.
- HSTS with `max-age=63072000; includeSubDomains; preload`.
- Certificate pinning on the mobile client (future phase).
- All cookies: `Secure; HttpOnly; SameSite=Strict`.
- CORS: explicit allowlist of origins, not `*`.
- `X-Content-Type-Options: nosniff`.
- `Content-Security-Policy` header with strict-dynamic nonce.
- `Referrer-Policy: no-referrer`.

### 5.5 JWT Token Design

| Token | Algorithm | TTL | Contents |
|---|---|---|---|
| Access Token | RS256 (asymmetric) | 15 minutes | `sub`, `jti`, `iat`, `exp`, `email`, `roles`, `security_stamp`, `org_ids` |
| Refresh Token | opaque 256-bit | 30 days | stored in DB as SHA-256 hash |

Access token is short-lived. The server validates:
1. Signature (RSA public key).
2. `exp` not in the past.
3. `security_stamp` matches the current value in the `users` collection. If the user changes their master password, security_stamp is rotated, invalidating all live access tokens instantly.

Refresh token rotation: every use of a refresh token issues a new one and revokes the old. If the same refresh token is used twice (family ID mismatch), the entire family is revoked — this is a detected token theft.

### 5.6 Two-Factor Authentication

| Method | Implementation |
|---|---|
| TOTP | RFC 6238, 30-second window, SHA-1 (standard), 6 digits. Library: `totp-rs`. |
| WebAuthn / FIDO2 | Platform authenticators (Face ID, Touch ID, Windows Hello) and security keys. Library: `webauthn-rs`. |
| Recovery Codes | 8 × 8-character alphanumeric codes, each Argon2id-hashed, single-use. |

2FA is enforced at login after password verification. The 2FA check is a separate API step to allow for the challenge-response flow.

### 5.7 Threat Model & Mitigations

| Threat | Vector | Mitigation |
|---|---|---|
| Database breach | Attacker reads all MongoDB data | Zero-knowledge: all vault data is encrypted. Server-side Argon2id on MPH means brute-force is slow even with the hash. |
| Master password brute-force | Online attack against `/auth/login` | Argon2id client-side (slow to compute), rate limiting, account lockout after 5 failures, CAPTCHA after 3. |
| Password spray | Low-and-slow across many accounts | Per-IP rate limiting (sliding window), progressive delay, audit alerts on 50+ failures per hour. |
| MITM | Intercept traffic | TLS 1.3, HSTS preloading, HPKP (on mobile). |
| JWT theft | XSS, log injection | Access token is 15-min TTL. Stored in memory (not localStorage) in browser. HttpOnly refresh token cookie. |
| Refresh token theft | Cookie theft, network sniff | HTTPS only, HttpOnly cookie, rotation with family detection. Immediate revocation on double-use. |
| Session fixation | Attacker plants session | JWT is stateless and user-derived; no session IDs to fix. Refresh token rotated on every use. |
| Credential stuffing | Replaying breached passwords | Argon2id makes each guess expensive (~500ms). Rate limiting. HIBP integration warns users on weak passwords. |
| Privilege escalation | RBAC bypass in code | RBAC middleware layer enforced before every handler. Unit tested for each permission matrix cell. |
| Insider threat (server admin) | Admin reads DB | Encrypted at rest, encrypted in transit, zero-knowledge. Admin cannot decrypt vault items. |
| Mass delete attack | Authenticated user deletes everything | Soft-delete only (trash). 30-day recovery window. Rate limit on delete operations. |
| Timing attacks | Compare hashes in variable time | All comparisons use `constant_time_eq`. Argon2 verify returns only bool. |
| Memory scraping | Process memory dump | Zero secrets held in `String` beyond the request. Use `secrecy::Secret<T>` and `zeroize::Zeroize`. |
| Supply chain | Malicious Cargo dependency | `cargo-audit` in CI. Dependency lockfile committed. SBOM generated on release. |
| Log injection | Inject newlines into audit log | Structured JSON logging (tracing-subscriber). No string interpolation in log messages. |

---

## 6. RBAC Design

### 6.1 System Roles

| Role | Scope | Capabilities |
|---|---|---|
| `super_admin` | Global | Manage all users, orgs, billing. System config. |
| `user` | Self | Own vault only. Default role. |
| `api_access` | Self | Machine-to-machine. No 2FA requirement (uses API key auth instead). |

### 6.2 Organization Roles

| Role | Manage Members | Manage Collections | View All Items | Write Items | Export Vault |
|---|---|---|---|---|---|
| Owner | ✓ | ✓ | ✓ | ✓ | ✓ |
| Admin | ✓ | ✓ | ✓ | ✓ | With permission |
| Manager | Own team only | Own collections | Collection-scoped | Collection-scoped | ✗ |
| Member | ✗ | ✗ | Collection-scoped | Collection-scoped | ✗ |
| Viewer | ✗ | ✗ | Collection-scoped | ✗ | ✗ |
| Custom | Configurable | Configurable | Configurable | Configurable | Configurable |

### 6.3 Collection-Level Access Override

Each `org_member.collections` entry is:
```json
{
  "collection_id": "...",
  "read_only": false,
  "hide_passwords": false,
  "manage": false
}
```

This overrides the org role for that specific collection.

### 6.4 Permission Check Flow

```
Request arrives
  │
  ├─► JWT auth middleware
  │     ├─ Decode and verify token
  │     ├─ Check security_stamp matches DB
  │     └─ Inject user context into request extensions
  │
  ├─► RBAC middleware (tower layer)
  │     ├─ Extract required permission from route metadata
  │     ├─ Check system role
  │     ├─ If org resource: check org membership + org role
  │     ├─ If collection resource: check collection-level override
  │     └─ Return 403 on any failure
  │
  └─► Handler
        └─ Also validates resource ownership in query:
             .find({"_id": id, "user_id": current_user.id})
```

The double-check (middleware + query predicate) is defence-in-depth: even if middleware is bypassed, the MongoDB query will return no document.

---

## 7. Rate Limiting

### 7.1 Strategy

Redis-backed sliding window counter. Each counter has a TTL equal to the window size. The key format:

```
rate:{bucket_type}:{identifier}:{endpoint_group}:{window_start_unix}
```

### 7.2 Limits Table

| Endpoint Group | Identifier | Window | Limit | Penalty |
|---|---|---|---|---|
| `POST /auth/login` | IP + Email | 5 min | 5 attempts | Exponential backoff + CAPTCHA |
| `POST /auth/register` | IP | 1 hour | 10 | Hard block 1 hour |
| `POST /auth/refresh` | User ID | 5 min | 20 | Block 5 min |
| `POST /auth/two-factor` | IP | 10 min | 10 | Block 10 min |
| `GET /vault/items` | User ID | 1 min | 60 | 429 |
| `POST /vault/items` | User ID | 1 min | 30 | 429 |
| `PUT /vault/items/*` | User ID | 1 min | 30 | 429 |
| `DELETE /vault/items/*` | User ID | 1 min | 10 | 429 |
| `GET /vault/items/*/password` | User ID | 1 min | 10 | 429 |
| Global catch-all | IP | 1 min | 200 | 429 |

### 7.3 Response Headers

Every response includes:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1706000000
Retry-After: 13       (only on 429)
```

### 7.4 Implementation (Rust Tower Layer)

```rust
pub struct RateLimitLayer {
    redis: Arc<RedisPool>,
    config: RateLimitConfig,
}

// Sliding window algorithm in Redis using MULTI/EXEC:
// ZADD key:window NX current_time request_id
// ZREMRANGEBYSCORE key:window -inf (current_time - window_ms)
// ZCARD key:window
// EXPIRE key:window window_seconds
// Returns count after cleanup
```

---

## 8. Idempotency

### 8.1 Why

Network failures can cause clients to retry POST/PUT requests, creating duplicates (e.g. two identical vault items). Idempotency keys ensure any retry returns the same response as the original.

### 8.2 Contract

- Client generates a UUID v4 and sends it in the `Idempotency-Key` header on any mutating request (POST, PUT, PATCH, DELETE).
- Server checks MongoDB `idempotency_records` before executing the handler.
- If a record exists with a matching key + user_id: return the stored response verbatim with `X-Idempotency-Replayed: true`.
- If no record: execute normally, store `{key, user_id, method, path, status_code, response_body}` atomically after the handler completes.
- TTL: 24 hours. After that, the key is gone and a new request with the same key is treated as fresh.
- Conflict: if a key is in-flight (another request is processing it right now), return `409 Conflict` with `Retry-After: 1`.

### 8.3 Scope

The idempotency key is scoped to `(user_id, idempotency_key)`. Two different users can use the same key without conflict.

### 8.4 Endpoints that require idempotency keys

- `POST /vault/items` — create item
- `POST /vault/collections` — create collection
- `POST /auth/register` — register user
- `POST /organizations` — create org
- `POST /organizations/:id/members` — invite member
- `DELETE /vault/items/:id` — delete (to prevent double-delete)

---

## 9. API Design

### 9.1 Conventions

- Base URL: `https://api.vaultrs.dev/v1`
- All bodies: `application/json`
- Auth: `Authorization: Bearer <access_token>` (except `/auth/*`)
- Versioned: `/v1/`
- Errors follow RFC 9457 Problem Details:
  ```json
  {
    "type": "https://vaultrs.dev/errors/validation",
    "title": "Validation Error",
    "status": 422,
    "detail": "Field 'email' is not a valid email address.",
    "instance": "/v1/auth/register",
    "trace_id": "01HQ..."
  }
  ```
- Pagination: cursor-based (`?after=<last_id>&limit=50`)
- Timestamps: ISO 8601 UTC
- IDs in responses: `public_id` (UUIDv4), never MongoDB ObjectId

### 9.2 Authentication Endpoints

```
POST   /v1/auth/register            Register new user
POST   /v1/auth/login               Step 1: password verify, returns partial token
POST   /v1/auth/two-factor          Step 2: TOTP/WebAuthn verify, returns full token pair
POST   /v1/auth/refresh             Exchange refresh token for new access token
POST   /v1/auth/logout              Revoke current refresh token
POST   /v1/auth/logout-all          Revoke all refresh tokens for user
GET    /v1/auth/me                  Current user profile (no vault data)
PUT    /v1/auth/password            Change master password (re-encrypts vault key)
POST   /v1/auth/two-factor/setup    Begin TOTP setup (returns QR code URI)
POST   /v1/auth/two-factor/confirm  Confirm TOTP with first code
DELETE /v1/auth/two-factor          Disable 2FA
```

### 9.3 Vault Item Endpoints

```
GET    /v1/vault/items                List items (encrypted, paginated)
POST   /v1/vault/items                Create item
GET    /v1/vault/items/:id            Get single item (encrypted)
PUT    /v1/vault/items/:id            Replace item
PATCH  /v1/vault/items/:id            Partial update (e.g. toggle favourite)
DELETE /v1/vault/items/:id            Soft delete (move to trash)
POST   /v1/vault/items/:id/restore    Restore from trash
DELETE /v1/vault/items/:id/permanent  Permanent delete

POST   /v1/vault/items/import         Bulk import (idempotent)
GET    /v1/vault/items/export         Bulk export (encrypted JSON)

GET    /v1/vault/items/:id/history    Password change history
```

### 9.4 Collection Endpoints

```
GET    /v1/vault/collections          List collections
POST   /v1/vault/collections          Create collection
GET    /v1/vault/collections/:id      Get collection
PUT    /v1/vault/collections/:id      Update collection
DELETE /v1/vault/collections/:id      Delete collection
GET    /v1/vault/collections/:id/items Items in a collection
```

### 9.5 Organization Endpoints

```
POST   /v1/organizations                        Create org
GET    /v1/organizations/:id                    Get org
PUT    /v1/organizations/:id                    Update org
GET    /v1/organizations/:id/members            List members
POST   /v1/organizations/:id/members            Invite member
PUT    /v1/organizations/:id/members/:uid/role  Change member role
DELETE /v1/organizations/:id/members/:uid       Remove member
GET    /v1/organizations/:id/audit              Org audit log
```

### 9.6 Audit & Admin Endpoints

```
GET    /v1/audit                      Personal audit log (paginated)
GET    /v1/admin/users                List all users (super_admin only)
POST   /v1/admin/users/:id/lock       Lock account
POST   /v1/admin/users/:id/unlock     Unlock account
GET    /v1/health                     Health check (no auth)
GET    /v1/health/ready               Readiness probe
```

---

## 10. Rust Project Structure

```
vaultrs/
├── Cargo.toml
├── Cargo.lock
├── .env.example
├── docker-compose.yml
│
├── src/
│   ├── main.rs                   # Entry point, server setup
│   ├── config.rs                 # Config from env (dotenvy + figment)
│   ├── error.rs                  # AppError, error mapping to HTTP
│   │
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── argon2.rs             # Password hashing + verification
│   │   ├── aes_gcm.rs            # Item encryption/decryption
│   │   ├── hkdf.rs               # Key derivation
│   │   └── rsa.rs                # Asymmetric key ops for sharing
│   │
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── auth.rs               # JWT extraction + validation
│   │   ├── rate_limit.rs         # Redis sliding window
│   │   ├── idempotency.rs        # Key check + store
│   │   ├── rbac.rs               # Permission enforcement
│   │   └── audit.rs              # Async audit log write
│   │
│   ├── routes/
│   │   ├── mod.rs                # Router assembly
│   │   ├── auth/
│   │   │   ├── mod.rs
│   │   │   ├── login.rs
│   │   │   ├── register.rs
│   │   │   ├── refresh.rs
│   │   │   ├── logout.rs
│   │   │   └── two_factor.rs
│   │   ├── vault/
│   │   │   ├── mod.rs
│   │   │   ├── items.rs
│   │   │   ├── collections.rs
│   │   │   └── import_export.rs
│   │   ├── organizations/
│   │   │   ├── mod.rs
│   │   │   ├── org.rs
│   │   │   └── members.rs
│   │   ├── audit.rs
│   │   ├── health.rs
│   │   └── admin/
│   │       └── users.rs
│   │
│   ├── services/
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── vault_service.rs
│   │   ├── collection_service.rs
│   │   ├── org_service.rs
│   │   ├── audit_service.rs
│   │   └── email_service.rs
│   │
│   ├── repositories/
│   │   ├── mod.rs
│   │   ├── user_repo.rs
│   │   ├── vault_item_repo.rs
│   │   ├── collection_repo.rs
│   │   ├── org_repo.rs
│   │   ├── audit_repo.rs
│   │   ├── refresh_token_repo.rs
│   │   └── idempotency_repo.rs
│   │
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── vault_item.rs
│   │   ├── collection.rs
│   │   ├── organization.rs
│   │   ├── audit_log.rs
│   │   └── common.rs             # Pagination, etc.
│   │
│   └── dto/
│       ├── mod.rs
│       ├── auth_dto.rs
│       ├── vault_dto.rs
│       └── org_dto.rs
│
└── tests/
    ├── integration/
    │   ├── auth_test.rs
    │   ├── vault_test.rs
    │   └── rbac_test.rs
    └── unit/
        ├── crypto_test.rs
        └── rate_limit_test.rs
```

---

## 11. Key Rust Crates

| Crate | Version | Purpose |
|---|---|---|
| `axum` | 0.7 | HTTP framework (Tower-based) |
| `tokio` | 1 | Async runtime |
| `mongodb` | 3 | MongoDB async driver |
| `redis` | 0.25 | Redis client (rate limit, idempotency) |
| `argon2` | 0.5 | Argon2id password hashing |
| `aes-gcm` | 0.10 | AES-256-GCM encryption |
| `hkdf` | 0.12 | HKDF key derivation |
| `rsa` | 0.9 | RSA-OAEP for vault sharing |
| `jsonwebtoken` | 9 | JWT encode/decode, RS256 |
| `totp-rs` | 5 | TOTP 2FA |
| `webauthn-rs` | 0.5 | WebAuthn/FIDO2 |
| `serde` | 1 | Serialisation |
| `serde_json` | 1 | JSON |
| `uuid` | 1 | UUIDv4 generation |
| `validator` | 0.18 | Input validation with derive macros |
| `secrecy` | 0.8 | Secret<T> wrapper, prevents accidental logging |
| `zeroize` | 1 | Wipe secrets from memory on drop |
| `tower` | 0.4 | Middleware composition |
| `tower-http` | 0.5 | CORS, trace, compression, HSTS |
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Log formatting, JSON output |
| `dotenvy` | 0.15 | `.env` loading |
| `thiserror` | 1 | Error derivation |
| `anyhow` | 1 | Error context in services |
| `chrono` | 0.4 | DateTime |
| `base64` | 0.22 | Encoding for ciphertext |
| `sha2` | 0.10 | SHA-256 for token hashing |
| `constant_time_eq` | 0.3 | Timing-safe comparison |
| `rand` | 0.8 | CSPRNG via OS entropy |
| `lettre` | 0.11 | Email (verification, alerts) |

---

## 12. MongoDB Index Strategy

```javascript
// users
db.users.createIndex({ email: 1 }, { unique: true })
db.users.createIndex({ public_id: 1 }, { unique: true })
db.users.createIndex({ deleted_at: 1 }, { sparse: true })

// vault_items
db.vault_items.createIndex({ user_id: 1, deleted_at: 1 })
db.vault_items.createIndex({ user_id: 1, type: 1 })
db.vault_items.createIndex({ collection_ids: 1 })
db.vault_items.createIndex({ public_id: 1 }, { unique: true })
db.vault_items.createIndex({ updated_at: -1 })

// refresh_tokens
db.refresh_tokens.createIndex({ token_hash: 1 }, { unique: true })
db.refresh_tokens.createIndex({ user_id: 1 })
db.refresh_tokens.createIndex({ expires_at: 1 }, { expireAfterSeconds: 0 }) // TTL

// audit_logs
db.audit_logs.createIndex({ actor_user_id: 1, created_at: -1 })
db.audit_logs.createIndex({ organization_id: 1, created_at: -1 })
db.audit_logs.createIndex({ created_at: 1 }, { expireAfterSeconds: 7776000 }) // 90 days TTL

// idempotency_records
db.idempotency_records.createIndex({ _id: 1, user_id: 1 })
db.idempotency_records.createIndex({ created_at: 1 }, { expireAfterSeconds: 86400 }) // 24h TTL

// org_members
db.org_members.createIndex({ organization_id: 1, user_id: 1 }, { unique: true })
db.org_members.createIndex({ user_id: 1 })
```

---

## 13. Environment Configuration

```env
# Server
HOST=0.0.0.0
PORT=8080
RUST_LOG=info

# MongoDB
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net
MONGODB_DB=vaultrs_prod

# Redis
REDIS_URL=redis://:password@localhost:6379/0

# JWT (RS256)
JWT_PRIVATE_KEY_PATH=/secrets/jwt_private.pem   # RSA-4096
JWT_PUBLIC_KEY_PATH=/secrets/jwt_public.pem
JWT_ACCESS_EXPIRY_SECONDS=900                    # 15 min
JWT_REFRESH_EXPIRY_SECONDS=2592000              # 30 days

# Argon2id (server-side hash of MPH)
ARGON2_MEMORY_KIB=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=4

# CORS
ALLOWED_ORIGINS=https://app.vaultrs.dev

# Email
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.xxx
FROM_EMAIL=noreply@vaultrs.dev

# Feature flags
REQUIRE_EMAIL_VERIFICATION=true
HIBP_CHECK_ENABLED=true
TOTP_REQUIRED=false
```

---

## 14. Development Milestones

### Phase 1 — Foundation (Weeks 1-2)
- [ ] Project scaffolding: workspace, crates, CI pipeline (GitHub Actions)
- [ ] MongoDB connection pool, Redis connection
- [ ] Config loading with validation
- [ ] Error handling framework
- [ ] Health check endpoint

### Phase 2 — Auth (Weeks 3-4)
- [ ] User registration with Argon2id
- [ ] Login flow (password → JWT pair)
- [ ] Refresh token rotation
- [ ] Logout + logout-all
- [ ] JWT middleware
- [ ] Rate limiting middleware (Redis)
- [ ] Email verification flow

### Phase 3 — Vault Core (Weeks 5-6)
- [ ] CRUD for vault items (encrypted data, opaque to server)
- [ ] Collections CRUD
- [ ] Soft delete + trash restore
- [ ] Favourite toggle
- [ ] Idempotency middleware + store
- [ ] Audit log (async)

### Phase 4 — Security Hardening (Weeks 7-8)
- [ ] TOTP 2FA setup + enforcement
- [ ] Account lockout + progressive delay
- [ ] RBAC middleware + permission matrix
- [ ] HIBP breach check on password
- [ ] Security stamp rotation on password change
- [ ] Refresh token family theft detection

### Phase 5 — Teams & Sharing (Weeks 9-10)
- [ ] Organization CRUD
- [ ] RSA key pair generation per user
- [ ] Vault sharing (encrypt org vault key with user public key)
- [ ] Org member RBAC
- [ ] Emergency access flow

### Phase 6 — Production Readiness (Weeks 11-12)
- [ ] WebAuthn / FIDO2 2FA
- [ ] Import/export (Bitwarden-compatible encrypted JSON)
- [ ] Structured JSON logging + distributed tracing (OpenTelemetry)
- [ ] Docker image + Helm chart
- [ ] Load testing (criterion benchmarks + k6)
- [ ] Security audit (cargo-audit, clippy, manual review)

---

## 15. Security Checklist (Pre-Production)

- [ ] All secrets loaded from environment, never hardcoded.
- [ ] `cargo audit` passes with zero vulnerabilities.
- [ ] All test passwords use `secrecy::Secret<String>` and `zeroize` on drop.
- [ ] No vault plaintext appears in logs (tested with log capture in CI).
- [ ] All cryptographic comparisons use `constant_time_eq`.
- [ ] OWASP Top 10 reviewed and addressed for each API endpoint.
- [ ] Penetration test or red-team exercise before first external user.
- [ ] Dependency lockfile (`Cargo.lock`) committed and reproducible builds verified.
- [ ] SBOM (Software Bill of Materials) generated with `cargo sbom`.
- [ ] MongoDB auth enabled, TLS between app and DB, IP allowlist.
- [ ] Redis AUTH enabled, TLS between app and Redis.
- [ ] JWT signing keys rotated on a schedule (key rotation procedure documented).
- [ ] Rate limits tested under load.
- [ ] Audit log verified to be write-only from application code.
- [ ] Disaster recovery tested: DB restore, key restore, full-stack rebuild.

---

*Document version: 1.0 | Date: 2026-03-18 | Author: VaultRS Design Review*