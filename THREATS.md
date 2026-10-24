# TrustVault Threat Model & Security Architecture Analysis

## 1. Executive Summary & Trust Boundaries
**TrustVault** is a zero-trust document storage and sharing web application designed for high-assurance access control. The architecture operates on the principle of **least privilege** and **deny-by-default**: no resource access, view, download, modification, or administrative action is permitted unless verified server-side at the moment of request execution.

### Architectural Trust Boundaries:
```
           [ Untrusted Client / Browser ]
                         |
           (HTTPS / Strict Security Headers / CSRF Token)
                         v
  +-------------------------------------------------------------+
  | Application Trust Boundary (Flask Web Application)          |
  |  - Session Authentication & Fixation Defense                |
  |  - CSRF Validation (hmac.compare_digest)                    |
  |  - Server-Side Authorization Engine (Deny-by-Default)       |
  |  - File Inspection (Magic Bytes, Size, Whitelist Extension) |
  |  - Append-Only Audit Logger                                 |
  +-------------------------------------------------------------+
         |                                             |
         v (Isolated Internal File System)             v (Parameterized SQL)
  +-----------------------------+               +------------------------------+
  | vault_storage/              |               | trustvault.db (SQLite)       |
  | - Outside web root          |               | - Foreign Keys Enforced      |
  | - Random UUID filenames     |               | - Append-Only Audit Triggers |
  | - No direct public URLs     |               | - Scrypt Password Hashes     |
  +-----------------------------+               +------------------------------+
```

---

## 2. STRIDE Threat Matrix & Countermeasure Mapping

| STRIDE Category | Threat Description | Attack Vector / Scenario | TrustVault Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Credential guessing / brute force | Attacker attempts password spraying. | Strong password complexity enforced on registration; Werkzeug `scrypt` hashing with unique per-user salts. Generic error messages prevent account enumeration. |
| **Spoofing** | Session Fixation | Attacker injects a pre-authenticated session cookie before the victim signs in. | `session.clear()` is called immediately upon successful authentication before establishing new identity tokens. |
| **Tampering** | Insecure Direct Object References (IDOR / BOLA) | Attacker manipulates `doc_id` in URL `/documents/42/download` or `/documents/42/delete`. | **Never trust client-supplied IDs.** Every operation executes `check_document_permission()` using authenticated `session['user_id']` against the database. |
| **Tampering** | Cross-Site Request Forgery (CSRF) | Attacker lures user to third-party page submitting a POST request to grant permissions or delete documents. | Session-bound cryptographically random CSRF tokens (`secrets.token_hex(32)`) checked on all state-changing verbs via timing-resistant `hmac.compare_digest`. SameSite cookie policy enforced. |
| **Tampering** | File disguise / Executable upload | Attacker uploads `malicious.exe` renamed to `contract.pdf`. | Multi-tier file validation: extension whitelist, MIME check, and **magic bytes signature inspection** (e.g., verifying `%PDF-` prefix and blocking `MZ`/`ELF` executables). |
| **Tampering** | Audit Log Alteration | Malicious user or rogue insider attempts SQL `UPDATE` or `DELETE` on `audit_logs`. | SQLite database triggers (`BEFORE UPDATE` and `BEFORE DELETE`) raise errors aborting transactions. Application exposes zero update/delete routes for logs. *(See Section 3 for limitations).* |
| **Repudiation** | Action Deniability | User claims they did not download or delete a sensitive document. | High-fidelity append-only audit trail logging user ID, email, action type, document ID, client IP address, timestamp, and status. |
| **Information Disclosure** | Direct Public Storage Access | Attacker accesses documents via predictable URLs like `/static/uploads/contract.pdf`. | Files are stored in `vault_storage/` **strictly outside the public/static directory**. Server serves files solely through authenticated `/download` controller via `send_file()`. |
| **Information Disclosure** | Path Traversal | Filename with `../../etc/passwd` or overwrite existing documents. | Uploaded files are stripped of user-controlled names and assigned **random server-generated UUID names** (`secrets.token_hex(16).ext`). |
| **Information Disclosure** | Detailed Stack Trace Leaks | Malformed requests triggering internal exceptions revealing database schemas or filesystem paths. | Production error handlers for 400, 401, 403, 404, 413, and 500 render generic user-facing templates. |
| **Denial of Service** | Storage exhaustion / ZIP bombs | Attacker uploads hundreds of gigabytes of data. | `MAX_CONTENT_LENGTH = 16 * 1024 * 1024` (16MB) strictly enforced at web framework boundary before streaming full payloads to disk. |
| **Elevation of Privilege** | Self-Provisioning Admin Role | Attacker modifies form POST payload `role=administrator` during registration. | Self-service registration route restricts role selection to `viewer` or `document_owner`. Selecting `administrator` is caught, rejected (HTTP 400), and logged as a security alert. |
| **Elevation of Privilege** | Horizontal & Vertical Access | Viewer attempts to access `/admin/dashboard` or upload documents. | Role-based decorators (`@admin_required`, `@roles_required`) verify server-side session role and abort with HTTP 403 and `PRIVILEGE_ESCALATION_ATTEMPT` audit logging. |

---

## 3. Critical Analysis: Audit Log Tampering Risks & SQLite Limitations

### Why SQLite Alone Does Not Guarantee Tamper-Proof Logs:
TrustVault incorporates defense-in-depth against log tampering:
1. **Application Layer:** No update or deletion code or endpoints exist for `audit_logs`.
2. **Database Engine Layer:** SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers call `SELECT RAISE(FAIL, ...)` to reject alterations through standard SQL queries.

### Remaining Residual Risks:
1. **Host-Level File System Access:** An attacker with local operating system access or physical access to `trustvault.db` can edit the file directly using a binary editor or raw SQLite driver without triggering triggers.
2. **Database Superuser / Trigger Dropping:** An attacker gaining arbitrary SQL injection or database administrative access could execute `DROP TRIGGER prevent_audit_delete;` and subsequently modify or truncate records.
3. **Storage Volatility:** A storage volume failure or intentional file deletion (`rm trustvault.db`) deletes both the operational state and the audit trail simultaneously.

### Production Enterprise Mitigations:
For high-assurance regulatory compliance (e.g., SOC 2 Type II, ISO 27001, HIPAA):
- **Off-Host Syslog / SIEM Shipping:** Stream audit events asynchronously via TLS to an immutable centralized log aggregator (e.g., Splunk, AWS CloudWatch Logs with Object Lock, Datadog).
- **Write-Once-Read-Many (WORM) Storage:** Store archived audit logs on immutable cloud buckets configured with retention locks (e.g., AWS S3 Glacier Vault Lock).
- **Cryptographic Chaining:** Chain audit entries using Merkle trees or SHA-256 block hashes (analogous to RFC 6962 Certificate Transparency), where each entry includes the hash of the preceding entry, making retroactive alterations mathematically detectable.

---

## 4. Server-Side Authorization & Immediate Revocation

### The Immediate Revocation Advantage:
Many modern web applications use stateless JWTs (JSON Web Tokens) with 1-hour expiration times. If an owner revokes a user's permission, the user can continue accessing and downloading sensitive documents until their token expires unless complex token revocation blocklists are implemented.

TrustVault avoids this vulnerability:
1. Every read, download, edit, or delete request queries the `document_permissions` table in real time.
2. When an owner clicks "Revoke", the permission row is deleted in the database within an ACID transaction.
3. The very next HTTP request issued by the revoked user fails the `check_document_permission()` query and is immediately blocked with HTTP 403.
