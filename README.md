# TrustVault - Secure Full-Stack Document Management System

**Built for the Snovasys Fresher Hiring Challenge 2026**

TrustVault is a zero-trust, full-stack web application designed for secure document storage, fine-grained access control, and complete audit logging. Built with Python Flask, SQLite, HTML5, CSS3, Bootstrap 5, and pytest.

---

## 1. System Architecture & Core Security Decisions

```
[ Browser / Client ]  <--->  [ Flask Web Application ]  <--->  [ SQLite (trustvault.db) ]
                                    |
                                    v
                           [ vault_storage/ ]
                    (Isolated outside static root)
```

### Core Security Principles Implemented:
1. **Deny-by-Default Authorization:** Every read, download, edit, and deletion dynamically verifies permissions on the server using `session['user_id']`. Client-supplied IDs and roles are never trusted.
2. **Immediate Revocation:** Permissions are queried from SQLite in real-time. Revoking access takes effect instantly on subsequent requests without caching delays.
3. **Storage Isolation:** Files are stored in `vault_storage/` (outside the public `static/` directory) using unpredictable server-generated 128-bit hex tokens (`secrets.token_hex(16).ext`). Direct public URLs do not exist.
4. **Magic Byte Content Validation:** Uploaded files undergo extension whitelisting, size limits, and binary magic byte verification (verifying `%PDF-`, PNG signatures, UTF-8 text purity, and actively rejecting Windows `MZ` and Linux `ELF` executables).
5. **Append-Only Audit Trail:** All successful and denied actions are logged with user context, action type, IP address, and details. SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers reject database-level tampering attempts.
6. **Defense-in-Depth Session & CSRF:** Passwords hashed with Werkzeug `scrypt`. Session cookies configured with `HttpOnly=True`, `SameSite='Lax'`. Cryptographic double-submit CSRF tokens verified via timing-resistant `hmac.compare_digest`.

---

## 2. Development Seed Accounts (Local Testing Only)

> [!WARNING]
> These credentials are strictly provided for local evaluation and security test automation. Do not use these credentials in a production environment.

| Role | Email Address | Password | Permissions & Scope |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.local` | `Admin@TrustVault2026!` | Access to the Administrator Activity Dashboard, system-wide metrics, append-only audit trail filters, security alert detection, and user account management. |
| **Document Owner** | `owner@trustvault.local` | `Owner@TrustVault2026!` | Can upload, view, edit, download, and delete owned documents. Can grant and revoke named read/edit permissions to other users. |
| **Viewer** | `viewer@trustvault.local` | `Viewer@TrustVault2026!` | Can search, view metadata, and download documents that have been explicitly shared with them. Cannot upload, edit, delete, or grant access. |
| **Secondary Owner** | `otherowner@trustvault.local` | `Other@TrustVault2026!` | Used to verify cross-user isolation and automated IDOR (Insecure Direct Object Reference) prevention. |

*(Note: Quick-fill demo buttons were intentionally removed from the login page to prevent public password exposure. Use the credentials in the table above.)*

---

## 3. Local Setup & Quickstart

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- `pip` (Python package manager)

### Step 1: Install Dependencies
Open a terminal in the project root directory and run:
```bash
pip install -r requirements.txt
```

### Step 2: Initialize and Seed the Database
Run the setup script to create tables, install append-only triggers, and provision seed accounts:
```bash
python seed.py
```

### Step 3: Run the Application Locally
Start the local development server:
```bash
python run.py
```
Open your browser and navigate to:
**`http://127.0.0.1:5000`**

---

## 4. Automated Testing Suite

All 24 automated security and functionality tests can be executed via `pytest`:

```bash
pytest -v
```

### Test Coverage Highlights:
- **`tests/test_auth.py`**: Authentication for all three roles, session fixation defense (`session.clear()`), registration constraints, password complexity, and prohibition of self-provisioned administrator accounts.
- **`tests/test_security.py`**: Deny-by-default unauthenticated access, IDOR cross-user URL manipulation, direct download blocking, privilege escalation prevention, file upload magic-byte verification, and randomized server storage filenames.
- **`tests/test_permissions.py`**: Per-document named user grants (read vs edit), immediate revocation blocking subsequent requests, and deletion restrictions.
- **`tests/test_audit.py`**: Telemetry recording of success and denied events, and verification of SQLite append-only triggers rejecting `UPDATE` and `DELETE`.
- **`tests/test_csrf.py`**: Verification that state-changing POST requests lacking valid CSRF tokens are rejected with HTTP 400.

---

## 5. API & Route Documentation

### Authentication Routes (`/auth`)
| Method | Endpoint | Access Role | CSRF Protected | Description | Status Codes |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `GET` | `/auth/login` | Public | No | Renders login page (no demo credentials exposed publicly). | 200 |
| `POST` | `/auth/login` | Public | Yes | Authenticates credentials, regenerates session, issues CSRF token. | 200, 400, 401, 403 |
| `POST` | `/auth/logout` | Authenticated | Yes | Clears session and logs audit event. | 302 |
| `GET` | `/auth/register` | Public | No | Renders registration form. | 200 |
| `POST` | `/auth/register` | Public | Yes | Registers new `viewer` or `document_owner`. Rejects `administrator` role. | 302, 400 |

### Document Management Routes (`/documents`)
| Method | Endpoint | Access Role | CSRF Protected | Description | Status Codes |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `GET` | `/documents/` | Authenticated | No | Lists and searches documents. Shows owned and shared documents. | 200, 302 |
| `GET` | `/documents/upload` | Owner, Admin | No | Renders secure file upload form. | 200, 403 |
| `POST` | `/documents/upload` | Owner, Admin | Yes | Validates magic bytes, saves to isolated storage with UUID name, logs event. | 302, 400, 403 |
| `GET` | `/documents/<id>` | Authorized | No | Views document metadata and permission roster (server-authorized). | 200, 403, 404 |
| `GET` | `/documents/<id>/download`| Authorized | No | Streams file from isolated storage via `send_file()`. Records audit download. | 200, 403, 404 |
| `POST` | `/documents/<id>/edit` | Owner, Edit Perm | Yes | Updates metadata or replaces stored file. | 302, 400, 403, 404 |
| `POST` | `/documents/<id>/delete` | Owner Only | Yes | Permanently removes document file and metadata. | 302, 403, 404 |
| `POST` | `/documents/<id>/permissions/grant` | Owner Only | Yes | Grants `read` or `edit` permission to a named user. | 302, 400, 403, 404 |
| `POST` | `/documents/<id>/permissions/revoke`| Owner Only | Yes | Immediately revokes permission from a user. | 302, 403, 404 |

### Administrator Activity Dashboard (`/admin`)
| Method | Endpoint | Access Role | CSRF Protected | Description | Status Codes |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `GET` | `/admin/dashboard` | Admin Only | No | Security metrics, denied attempt alerts, filterable append-only audit trail. | 200, 403 |
| `POST` | `/admin/users/<id>/toggle-status` | Admin Only | Yes | Deactivates or reactivates a user account. | 302, 403, 404 |

---

## 6. Database Setup & Architecture

TrustVault uses SQLite with explicit foreign keys and trigger-based immutability.
- **Schema File:** `schema.sql`
- **Tables:**
  - `users`: ID, email, username, password_hash, role, is_active, created_at
  - `documents`: ID, title, description, category, tags, original_filename, stored_filename, file_size, mime_type, file_extension, owner_id, timestamps
  - `document_permissions`: ID, document_id, user_id, permission_level ('read'|'edit'), granted_by, created_at
  - `audit_logs`: ID, timestamp, user_id, user_email, action, document_id, resource, status ('SUCCESS'|'DENIED'|'ERROR'), ip_address, details
- **Triggers:**
  - `prevent_audit_update`: Blocks `UPDATE` queries on `audit_logs`.
  - `prevent_audit_delete`: Blocks `DELETE` queries on `audit_logs`.

---

## 7. Security Decision Defense Summary (For Interviews)

1. **Why session-based auth over stateless JWTs?**
   - *Direct and immediate revocation:* Stateless tokens cannot be revoked instantly without maintaining a distributed blocklist. Session checks against SQLite guarantee zero delay when permissions are revoked.
2. **Why store files outside `static/` with random UUID names?**
   - *Eliminates direct URL access and directory traversal:* Files cannot be requested directly by filename from web servers or reverse proxies. Every single download passes through Flask's permission-checking controller.
3. **Why inspect magic bytes instead of trusting client MIME type or extension?**
   - *Prevents executable disguise:* An attacker can name an `.exe` file `report.pdf`. Inspecting binary headers (`%PDF-`, `\x89PNG`) prevents polyglot and disguised malicious payloads from entering the storage vault.
4. **Why are SQLite triggers alone not completely tamper-proof?**
   - *Separation of database vs OS boundaries:* Triggers protect against SQL-level updates, but anyone with OS-level write access to the `.db` file can modify bytes directly. True enterprise immutability requires external write-once (WORM) storage or remote SIEM log shipping.

## 6. Render Deployment

This repository includes `render.yaml` for a Render web service.

1. Push the project to a Git repository and connect it to Render.
2. Review the Blueprint settings before deploying. Render should generate `SECRET_KEY` automatically.
3. The Blueprint mounts a persistent disk at `/var/data` and stores the SQLite database and uploaded files there. A persistent disk is required to preserve data across deploys; confirm that your Render plan supports it.
4. Demo accounts are **not seeded in production by default**. To enable the fixed development demo accounts for a controlled challenge demo, set `TRUSTVAULT_SEED_DEMO_ACCOUNTS=true` in Render environment variables. These predictable credentials are public in this repository's documentation, so do not enable this on a real or sensitive deployment.
5. After deployment, test login, upload/download, permission grant/revoke, denied access, and audit logs on the public URL. Check Render logs for startup errors.

For production use, replace the demo-account seeding approach with a one-time administrator provisioning procedure and use a managed database/object store if multiple instances or larger storage are required.

