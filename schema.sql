-- TrustVault Database Schema
-- Snovasys Fresher Hiring Challenge 2026

PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('administrator', 'document_owner', 'viewer')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents metadata table
-- Files are stored outside static folder with random UUID names
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT DEFAULT 'General',
    tags TEXT DEFAULT '',
    original_filename TEXT NOT NULL,
    stored_filename TEXT UNIQUE NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    file_extension TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Document permissions table (Per-document permissions for named users)
CREATE TABLE IF NOT EXISTS document_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    permission_level TEXT NOT NULL CHECK(permission_level IN ('read', 'edit')),
    granted_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(granted_by) REFERENCES users(id),
    UNIQUE(document_id, user_id)
);

-- Audit logs table (Append-only)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    user_email TEXT,
    action TEXT NOT NULL,
    document_id INTEGER,
    resource TEXT,
    status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'DENIED', 'ERROR')),
    ip_address TEXT,
    details TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Defense-in-depth: SQLite triggers to reject UPDATE and DELETE operations on audit_logs
CREATE TRIGGER IF NOT EXISTS prevent_audit_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(FAIL, 'Audit log is append-only: updates are strictly prohibited.');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(FAIL, 'Audit log is append-only: deletions are strictly prohibited.');
END;

-- Indexes for efficient queries and audit filtering
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_doc_perm_doc_user ON document_permissions(document_id, user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_logs(status);
