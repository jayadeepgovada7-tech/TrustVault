import hmac
import os
import secrets
import zipfile
import io
from flask import session, request, abort
from werkzeug.utils import secure_filename
from app.database import get_db
from app.audit import log_audit

# Magic byte signatures for supported file types
MAGIC_SIGNATURES = {
    'pdf': [b'%PDF-'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'jpg': [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
}

# Blocked dangerous executable signatures
DANGEROUS_SIGNATURES = [
    b'MZ',       # Windows DOS/PE Executable
    b'\x7fELF',  # Linux ELF Executable
    b'<!DOCTYPE html', # Embedded HTML / XSS vectors in disguised text
    b'<html',
    b'<script',
]

def generate_csrf_token():
    """Generate or retrieve a cryptographically secure CSRF token bound to the current session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf():
    """
    Validate CSRF token on state-changing requests.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        session_token = session.get('_csrf_token')
        
        if not token or not session_token or not hmac.compare_digest(str(token), str(session_token)):
            log_audit(
                action='CSRF_FAILURE',
                status='DENIED',
                resource=request.path,
                details=f"Invalid or missing CSRF token on {request.method} request"
            )
            abort(400, description="CSRF validation failed: Invalid or missing security token.")

# Resource limits for Office archives (decompression bombs & zip slip defense)
MAX_ZIP_ENTRIES = 500
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_COMPRESSION_RATIO = 100

PROHIBITED_ARCHIVE_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.scr',
    '.sh', '.bin', '.pif', '.com', '.cpl', '.hta', '.jar', '.py'
}

def validate_office_archive(file_bytes, ext):
    """
    Validate DOCX / XLSX archives:
    1. Valid ZIP structure
    2. Enforce resource limits (entries, uncompressed size, compression ratio)
    3. Block Zip Slip / path traversal in entry names
    4. Prohibit executable/script attachments inside archive
    5. Verify standard Office XML components
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            infolist = zf.infolist()
            
            # Resource limit: number of entries
            if len(infolist) > MAX_ZIP_ENTRIES:
                return False, f"Archive contains too many files ({len(infolist)} > {MAX_ZIP_ENTRIES})."
            
            total_uncompressed = 0
            compressed_total = max(len(file_bytes), 1)

            names = []
            for zinfo in infolist:
                name = zinfo.filename
                names.append(name)

                # Path traversal / Zip Slip prevention
                if '..' in name or name.startswith('/') or name.startswith('\\') or ':' in name:
                    return False, "Archive contains illegal or traversal file paths."

                # Prohibited executable extensions inside archive
                lower_name = name.lower()
                for bad_ext in PROHIBITED_ARCHIVE_EXTENSIONS:
                    if lower_name.endswith(bad_ext):
                        return False, f"Archive contains prohibited embedded file type: {bad_ext}"

                # Resource limits: decompression size & ratio
                total_uncompressed += zinfo.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                    return False, "Archive uncompressed volume exceeds safety limit (50 MB)."

            if (total_uncompressed / compressed_total) > MAX_COMPRESSION_RATIO:
                return False, "Abnormal compression ratio detected (potential zip bomb)."

            # Office package structural checks
            if '[Content_Types].xml' not in names:
                return False, f"Invalid .{ext} archive: missing [Content_Types].xml"

            if ext == 'docx':
                if not any(n.startswith('word/') for n in names) or 'word/document.xml' not in names:
                    return False, "Invalid .docx archive: missing Word document structures."
            elif ext == 'xlsx':
                if not any(n.startswith('xl/') for n in names) or 'xl/workbook.xml' not in names:
                    return False, "Invalid .xlsx archive: missing Excel workbook structures."

            return True, None
    except zipfile.BadZipFile:
        return False, f"Corrupted or invalid .{ext} zip container."


def sanitize_and_validate_file(file_storage, allowed_extensions, max_bytes):
    """
    Strict multi-tier file validation:
    1. Validate extension from filename
    2. Check file size limits
    3. Guard against dangerous executable and script formats
    4. Content signature verification (magic numbers)
    5. Deep archive inspection for DOCX / XLSX
    6. Generate a random, unpredictable server-side filename
    
    Returns: (is_valid, error_message, sanitized_original_name, stored_filename, ext, mime_type, file_size)
    """
    if not file_storage or not file_storage.filename:
        return False, "No file selected for upload.", None, None, None, None, 0
    
    # 1. Filename and extension check
    orig_name = secure_filename(file_storage.filename)
    if not orig_name:
        return False, "Invalid filename provided.", None, None, None, None, 0
    
    parts = orig_name.rsplit('.', 1)
    if len(parts) < 2:
        return False, "File must have an explicit extension.", None, None, None, None, 0
    
    ext = parts[1].lower()
    if ext not in allowed_extensions:
        return False, f"File extension '.{ext}' is not permitted. Allowed: {', '.join(sorted(allowed_extensions))}", None, None, None, None, 0

    # 2. Read content bytes for inspection
    file_bytes = file_storage.read()
    file_size = len(file_bytes)
    
    # Reset file pointer
    file_storage.seek(0)
    
    if file_size == 0:
        return False, "Empty files are not allowed.", None, None, None, None, 0
    
    if file_size > max_bytes:
        return False, f"File size exceeds maximum permitted limit ({max_bytes // (1024*1024)} MB).", None, None, None, None, 0

    # 3. Check for dangerous executable signatures across all files
    prefix_sample = file_bytes[:1024]
    for dangerous in DANGEROUS_SIGNATURES:
        if prefix_sample.startswith(dangerous) or dangerous.lower() in prefix_sample.lower()[:256]:
            return False, "Security validation rejected file: prohibited content signature detected.", None, None, None, None, 0

    # 4. Content signature verification for specific extensions
    detected_mime = file_storage.content_type or 'application/octet-stream'
    
    if ext == 'pdf':
        if not file_bytes.startswith(b'%PDF-'):
            return False, "File content does not match the signature for a valid .pdf file.", None, None, None, None, 0
        if len(file_bytes) < 16:
            return False, "PDF document structure is truncated or incomplete.", None, None, None, None, 0

    elif ext == 'png':
        if not file_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
            return False, "File content does not match the signature for a valid .png image.", None, None, None, None, 0
        if len(file_bytes) < 16 or file_bytes[12:16] != b'IHDR':
            return False, "Invalid PNG structure: missing IHDR header.", None, None, None, None, 0

    elif ext in ('jpg', 'jpeg'):
        if not file_bytes.startswith(b'\xff\xd8\xff'):
            return False, f"File content does not match the signature for a valid .{ext} image.", None, None, None, None, 0

    elif ext in ('txt', 'csv'):
        # Verify valid UTF-8/ASCII text without binary null bytes
        if b'\x00' in file_bytes:
            return False, "Text/CSV files cannot contain null binary bytes.", None, None, None, None, 0
        try:
            file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return False, "Text/CSV file must be valid UTF-8 encoded text.", None, None, None, None, 0

    elif ext in ('docx', 'xlsx'):
        # Deep inspection of Office archive container
        is_ok, err = validate_office_archive(file_bytes, ext)
        if not is_ok:
            return False, f"Office document validation failed: {err}", None, None, None, None, 0

    # 5. Generate unpredictable server storage filename (UUID hex)
    # Stored file name is NEVER derived from user input
    stored_name = f"{secrets.token_hex(16)}.{ext}"
    
    return True, None, orig_name, stored_name, ext, detected_mime, file_size


def check_document_permission(doc_id, user_id, user_role, required_action):
    """
    Enforces server-side authorization: Deny by default.
    
    Actions:
    - 'read' / 'download': allowed for document owner, administrator, or user with 'read' or 'edit' permission.
    - 'edit': allowed for document owner or user with 'edit' permission.
    - 'delete': allowed ONLY for document owner.
    - 'manage_permissions': allowed ONLY for document owner.
    
    Returns: (is_allowed, status_code, message, document_record)
    """
    if not user_id:
        return False, 401, "Authentication required", None

    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Fetch document (parameterized query)
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()
    
    if not doc:
        return False, 404, "Document not found", None

    is_owner = (doc['owner_id'] == user_id)
    is_admin = (user_role == 'administrator')

    # Owners have full rights
    if is_owner:
        return True, 200, "Owner access granted", doc

    # Only owner can delete or manage permissions
    if required_action in ('delete', 'manage_permissions'):
        return False, 403, f"Only the document owner can {required_action.replace('_', ' ')} this document", doc

    # Edit requires owner OR explicit 'edit' permission
    if required_action == 'edit':
        cursor.execute(
            """
            SELECT permission_level FROM document_permissions 
            WHERE document_id = ? AND user_id = ? AND permission_level = 'edit'
            """,
            (doc_id, user_id)
        )
        perm = cursor.fetchone()
        if perm:
            return True, 200, "Edit permission granted", doc
        return False, 403, "You do not have edit permission for this document", doc

    # Read / Download: Requires document ownership or explicit granted permission (applies to all users, including administrators)
    if required_action in ('read', 'download'):
        cursor.execute(
            """
            SELECT permission_level FROM document_permissions 
            WHERE document_id = ? AND user_id = ?
            """,
            (doc_id, user_id)
        )
        perm = cursor.fetchone()
        if perm and perm['permission_level'] in ('read', 'edit'):
            return True, 200, f"Granted {perm['permission_level']} access", doc
        return False, 403, "Access denied: you do not have permission to view or download this document", doc

    return False, 403, "Unknown action: access denied by default", doc
