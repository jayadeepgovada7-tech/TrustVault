# TrustVault Engineering Prompts & Architectural Rationale

This document tracks the architectural decisions, design tradeoffs, and technical defenses implemented for the **Snovasys Fresher Hiring Challenge 2026**.

---

## 1. Architectural Phases & Decomposition

### Phase 1: Threat Modeling & Trust Boundary Specification
* **Objective:** Define clear trust boundaries and identify high-risk vectors (IDOR, Path Traversal, Executable Upload, Session Fixation).
* **Key Decision:** Adopt **Server-Side Deny-by-Default** authorization. Never rely on client-side state, URL parameters, or cached claims for access decisions.

### Phase 2: Schema & Database Design with Defense-in-Depth
* **Objective:** Establish normalized relational schema supporting 3 roles (`administrator`, `document_owner`, `viewer`), granular per-document permissions, and immutable audit logs.
* **Key Decision:** Incorporate SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers directly in `schema.sql` to reject mutations on `audit_logs` at the database engine layer.
* **Database Constraints:** Enforce `PRAGMA foreign_keys = ON;` and unique constraints on `(document_id, user_id)`.

### Phase 3: File Storage Isolation & Multi-Layer Validation
* **Objective:** Prevent arbitrary code execution, file spoofing, and directory traversal.
* **Key Decisions:**
  1. **Storage Isolation:** Place `vault_storage/` completely outside the public web root (`static/`).
  2. **Random Server Names:** Store files using random 128-bit hex tokens (`secrets.token_hex(16).ext`), completely dissociating disk filenames from user-supplied strings.
  3. **Content Signature Verification:** Inspect binary magic bytes (e.g. verifying `%PDF-` for PDFs, `\x89PNG` for PNGs, checking for absence of null bytes in text files, and rejecting `MZ`/`ELF` executable binaries).

### Phase 4: Immediate Revocation Authorization Engine
* **Objective:** Ensure permission revocation takes effect with zero propagation delay.
* **Key Decision:** Validate permissions dynamically in the database upon each protected HTTP request rather than embedding permissions in stateless session tokens.

### Phase 5: Automated Security Testing & Zero-Trust Validation
* **Objective:** Build comprehensive automated tests verifying all security rules before marking work complete.
* **Test Matrix:** 24 distinct test scenarios verifying:
  - Authentication & session fixation protection
  - IDOR cross-user document manipulation
  - Direct download blocks
  - Privilege escalation blocks (viewer to admin, owner to admin, disallowed role registration)
  - Disguised malicious file uploads
  - Immediate revocation enforcement
  - Audit logging of successful and denied actions
  - Append-only database triggers
  - CSRF token validation

---

## 2. Interview Defense Guide: Key Security Tradeoffs

### Q1: Why use server-side sessions instead of JWTs for TrustVault?
* **Defense:**
  > *"JWTs are stateless, which makes immediate permission revocation difficult without maintaining a distributed revocation blocklist (which reintroduces state). Because TrustVault requires that an owner's permission revocation blocks subsequent access immediately, server-backed session state and direct database authorization checks guarantee zero stale access window."*

### Q2: Why is SQLite alone insufficient for audit log immutability?
* **Defense:**
  > *"While application-level restrictions and SQLite triggers prevent standard SQL `UPDATE` and `DELETE` commands, an adversary with filesystem access to `trustvault.db` or root operating system privileges can bypass database engine triggers entirely. For enterprise regulatory compliance, audit logs must be streamed off-host to write-once (WORM) storage or an immutable SIEM like AWS CloudWatch Logs or Splunk."*

### Q3: How do you prevent Insecure Direct Object Reference (IDOR)?
* **Defense:**
  > *"We never trust the document ID supplied by the client in the URL. Before performing any read, download, edit, or delete operation, the server extracts the authenticated `user_id` from the secure session and executes `check_document_permission()`, verifying ownership or explicit rows in `document_permissions`. If unauthorized, the request is aborted with HTTP 403 and logged as an `ACCESS_DENIED` security incident."*

### Q4: How is file upload secured against disguised malware?
* **Defense:**
  > *"We use a 4-tier validation pipeline: (1) extension whitelist, (2) maximum payload size limit (16MB), (3) magic byte signature inspection that checks actual file header bytes (e.g. verifying `%PDF-` and rejecting Windows `MZ` binaries), and (4) random UUID filenames saved outside the web root so direct execution is physically impossible."*
