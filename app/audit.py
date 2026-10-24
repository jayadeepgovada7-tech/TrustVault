from flask import request, session, has_request_context
from app.database import get_db

def log_audit(action, status, resource=None, document_id=None, details=None, user_id=None, user_email=None, ip_address=None):
    """
    Append an entry to the audit log.
    Enforces append-only semantics at the application level.
    
    Actions include:
    - AUTH_LOGIN_SUCCESS, AUTH_LOGIN_FAILED, AUTH_LOGOUT, AUTH_REGISTER
    - DOC_UPLOAD, DOC_READ, DOC_DOWNLOAD, DOC_EDIT, DOC_DELETE
    - PERM_GRANT, PERM_REVOKE
    - ACCESS_DENIED, CSRF_FAILURE, PRIVILEGE_ESCALATION_ATTEMPT
    
    Status: 'SUCCESS', 'DENIED', 'ERROR'
    """
    try:
        # Resolve user context if not explicitly passed
        if has_request_context():
            if user_id is None:
                user_id = session.get('user_id')
            if user_email is None:
                user_email = session.get('user_email')
            if ip_address is None:
                # Use request remote address
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
                if ip_address and ',' in ip_address:
                    ip_address = ip_address.split(',')[0].strip()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (
                user_id, user_email, action, document_id, resource, status, ip_address, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                user_email or 'anonymous',
                action,
                document_id,
                resource or 'GENERAL',
                status,
                ip_address or 'unknown',
                details or ''
            )
        )
        conn.commit()
    except Exception as e:
        # Audit logging failure should not expose internal trace to client,
        # but in production, this should trigger an immediate security alert.
        import sys
        sys.stderr.write(f"[SECURITY ALERT] Audit logging failed: {e}\n")
