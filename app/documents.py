import os
import re
from pathlib import Path
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, abort, send_file, current_app
)
from app.database import get_db
from app.auth import login_required, roles_required
from app.audit import log_audit
from app.security import (
    check_document_permission,
    sanitize_and_validate_file,
    generate_csrf_token
)

documents_bp = Blueprint('documents', __name__, url_prefix='/documents')

@documents_bp.route('/', methods=['GET'])
@login_required
def list_documents():
    """
    List and search documents accessible to the authenticated user.
    Enforces deny-by-default access control:
    - Administrators: can see all documents
    - Owners/Viewers: can ONLY see documents they own or have explicit granted permissions for.
    """
    user_id = session['user_id']
    user_role = session.get('role')
    
    # Search and filtering parameters
    search_query = request.args.get('q', '').strip()
    category_filter = request.args.get('category', '').strip()
    tag_filter = request.args.get('tag', '').strip()
    view_filter = request.args.get('view', 'all').strip()
    owner_filter = request.args.get('owner', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    conn = get_db()
    cursor = conn.cursor()

    # Base query joining document owner username
    base_sql = """
        SELECT DISTINCT d.*, u.username as owner_username, u.email as owner_email,
            CASE 
                WHEN d.owner_id = ? THEN 'owner'
                ELSE COALESCE(dp.permission_level, 'none')
            END as user_permission
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = ?
    """
    
    conditions = []
    params = [user_id, user_id]

    # Authorization filtering: All users (including administrators) require explicit ownership or grant
    if view_filter == 'owned':
        conditions.append("d.owner_id = ?")
        params.append(user_id)
    elif view_filter == 'shared':
        conditions.append("d.owner_id != ? AND dp.permission_level IS NOT NULL")
        params.append(user_id)
    else:
        conditions.append("(d.owner_id = ? OR dp.permission_level IS NOT NULL)")
        params.append(user_id)

    # Search query (title, description, tags, category)
    if search_query:
        search_param = f"%{search_query}%"
        conditions.append("(d.title LIKE ? OR d.description LIKE ? OR d.tags LIKE ? OR d.category LIKE ?)")
        params.extend([search_param, search_param, search_param, search_param])

    # Category filter
    if category_filter:
        conditions.append("d.category = ?")
        params.append(category_filter)

    # Tag filter
    if tag_filter:
        conditions.append("d.tags LIKE ?")
        params.append(f"%{tag_filter}%")

    # Owner filter (username or email)
    if owner_filter:
        owner_param = f"%{owner_filter}%"
        conditions.append("(u.username LIKE ? OR u.email LIKE ?)")
        params.extend([owner_param, owner_param])

    # Date range filters (ISO YYYY-MM-DD validation)
    date_regex = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    if date_from and date_regex.match(date_from):
        conditions.append("date(d.created_at) >= date(?)")
        params.append(date_from)
    if date_to and date_regex.match(date_to):
        conditions.append("date(d.created_at) <= date(?)")
        params.append(date_to)

    if conditions:
        full_sql = base_sql + " WHERE " + " AND ".join(conditions) + " ORDER BY d.created_at DESC"
    else:
        full_sql = base_sql + " ORDER BY d.created_at DESC"

    cursor.execute(full_sql, params)
    docs = cursor.fetchall()

    # Get distinct categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM documents WHERE category IS NOT NULL AND category != ''")
    categories = [row['category'] for row in cursor.fetchall()]

    return render_template(
        'dashboard.html',
        documents=docs,
        categories=categories,
        search_query=search_query,
        category_filter=category_filter,
        tag_filter=tag_filter,
        view_filter=view_filter,
        owner_filter=owner_filter,
        date_from=date_from,
        date_to=date_to
    )


@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
@roles_required('administrator', 'document_owner')
def upload_document():
    """
    Secure file upload:
    - Permitted for document_owner and administrator roles only
    - Validates file extension, MIME type, magic bytes, and file size
    - Saves file to storage folder outside web root with a cryptographically random UUID name
    """
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', 'General').strip() or 'General'
        tags = request.form.get('tags', '').strip()
        file = request.files.get('file')

        if not title:
            flash('Document title is required.', 'danger')
            return render_template('upload.html'), 400

        # Validate file
        is_valid, err_msg, orig_name, stored_name, ext, mime_type, file_size = sanitize_and_validate_file(
            file,
            current_app.config['ALLOWED_EXTENSIONS'],
            current_app.config['MAX_CONTENT_LENGTH']
        )

        if not is_valid:
            log_audit(
                action='DOC_UPLOAD',
                status='DENIED',
                resource='/documents/upload',
                details=f"File validation failed: {err_msg}"
            )
            flash(err_msg, 'danger')
            return render_template('upload.html'), 400

        # Save to secure storage folder
        storage_folder = Path(current_app.config['STORAGE_FOLDER'])
        storage_folder.mkdir(parents=True, exist_ok=True)
        dest_path = storage_folder / stored_name

        file.seek(0)
        file.save(dest_path)

        # Insert metadata into SQLite
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO documents (
                title, description, category, tags,
                original_filename, stored_filename, file_size,
                mime_type, file_extension, owner_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title, description, category, tags,
                orig_name, stored_name, file_size,
                mime_type, ext, session['user_id']
            )
        )
        doc_id = cursor.lastrowid
        conn.commit()

        log_audit(
            action='DOC_UPLOAD',
            status='SUCCESS',
            resource=f"/documents/{doc_id}",
            document_id=doc_id,
            details=f"Uploaded document '{title}' (original: {orig_name}, size: {file_size} bytes)"
        )

        flash(f"Document '{title}' uploaded successfully.", 'success')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    return render_template('upload.html')


@documents_bp.route('/<int:doc_id>', methods=['GET'])
@login_required
def view_document(doc_id):
    """
    View document details and permissions.
    Enforces server-side authorization: Owner, Admin, or users with explicit read/edit permission.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'read')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}",
            document_id=doc_id,
            details=f"View access denied: {message}"
        )
        abort(status_code, description=message)

    log_audit(
        action='DOC_READ',
        status='SUCCESS',
        resource=f"/documents/{doc_id}",
        document_id=doc_id,
        details=f"Viewed document metadata: '{doc['title']}'"
    )

    conn = get_db()
    cursor = conn.cursor()

    # Fetch document owner details
    cursor.execute("SELECT username, email FROM users WHERE id = ?", (doc['owner_id'],))
    owner = cursor.fetchone()

    # Determine user's specific permissions on this document
    is_owner = (doc['owner_id'] == user_id)
    cursor.execute(
        "SELECT permission_level FROM document_permissions WHERE document_id = ? AND user_id = ?",
        (doc_id, user_id)
    )
    user_perm_row = cursor.fetchone()
    user_permission = 'owner' if is_owner else (user_perm_row['permission_level'] if user_perm_row else 'none')

    # Only document owner can view and manage permissions roster
    granted_permissions = []
    available_users = []
    if is_owner:
        cursor.execute(
            """
            SELECT dp.*, u.username, u.email 
            FROM document_permissions dp
            JOIN users u ON dp.user_id = u.id
            WHERE dp.document_id = ?
            ORDER BY dp.created_at DESC
            """,
            (doc_id,)
        )
        granted_permissions = cursor.fetchall()

        # Fetch other active users who don't own the document and don't yet have permissions
        cursor.execute(
            """
            SELECT id, username, email, role FROM users 
            WHERE id != ? AND is_active = 1
            AND id NOT IN (SELECT user_id FROM document_permissions WHERE document_id = ?)
            ORDER BY username ASC
            """,
            (doc['owner_id'], doc_id)
        )
        available_users = cursor.fetchall()

    return render_template(
        'doc_detail.html',
        doc=doc,
        owner=owner,
        is_owner=is_owner,
        user_permission=user_permission,
        granted_permissions=granted_permissions,
        available_users=available_users
    )


@documents_bp.route('/<int:doc_id>/download', methods=['GET'])
@login_required
def download_document(doc_id):
    """
    Secure file download:
    - Never exposes direct public file URLs.
    - Server-side authorization check for every request.
    - Resolves file outside static directory and sends via send_file.
    - Records successful and denied downloads in audit trail.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'download')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}/download",
            document_id=doc_id,
            details=f"Unauthorized download attempt: {message}"
        )
        abort(status_code, description=message)

    # Locate secure storage file
    file_path = Path(current_app.config['STORAGE_FOLDER']) / doc['stored_filename']
    if not file_path.exists():
        log_audit(
            action='DOC_DOWNLOAD',
            status='ERROR',
            resource=f"/documents/{doc_id}/download",
            document_id=doc_id,
            details=f"File missing on disk: {doc['stored_filename']}"
        )
        abort(404, description="File not found on storage backend.")

    log_audit(
        action='DOC_DOWNLOAD',
        status='SUCCESS',
        resource=f"/documents/{doc_id}/download",
        document_id=doc_id,
        details=f"Downloaded '{doc['original_filename']}' ({doc['file_size']} bytes)"
    )

    return send_file(
        file_path,
        as_attachment=True,
        download_name=doc['original_filename'],
        mimetype=doc['mime_type']
    )


@documents_bp.route('/<int:doc_id>/edit', methods=['POST'])
@login_required
def edit_document(doc_id):
    """
    Edit document metadata or replace file:
    - Requires 'edit' permission or document ownership.
    - Client-supplied document ID is strictly authorized server-side.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'edit')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}/edit",
            document_id=doc_id,
            details=f"Unauthorized edit attempt: {message}"
        )
        abort(status_code, description=message)

    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', '').strip() or 'General'
    tags = request.form.get('tags', '').strip()

    if not title:
        flash('Title cannot be empty.', 'danger')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    conn = get_db()
    cursor = conn.cursor()

    # Optional file replacement
    replacement_file = request.files.get('replacement_file')
    if replacement_file and replacement_file.filename:
        is_valid, err_msg, orig_name, stored_name, ext, mime_type, file_size = sanitize_and_validate_file(
            replacement_file,
            current_app.config['ALLOWED_EXTENSIONS'],
            current_app.config['MAX_CONTENT_LENGTH']
        )
        if not is_valid:
            flash(f"File replacement failed: {err_msg}", 'danger')
            return redirect(url_for('documents.view_document', doc_id=doc_id))

        # Save new file and remove old file
        storage_folder = Path(current_app.config['STORAGE_FOLDER'])
        dest_path = storage_folder / stored_name
        replacement_file.seek(0)
        replacement_file.save(dest_path)

        old_file_path = storage_folder / doc['stored_filename']
        if old_file_path.exists():
            try:
                os.remove(old_file_path)
            except OSError:
                pass

        cursor.execute(
            """
            UPDATE documents
            SET title = ?, description = ?, category = ?, tags = ?,
                original_filename = ?, stored_filename = ?, file_size = ?,
                mime_type = ?, file_extension = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                title, description, category, tags,
                orig_name, stored_name, file_size,
                mime_type, ext, doc_id
            )
        )
    else:
        cursor.execute(
            """
            UPDATE documents
            SET title = ?, description = ?, category = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (title, description, category, tags, doc_id)
        )

    conn.commit()

    log_audit(
        action='DOC_EDIT',
        status='SUCCESS',
        resource=f"/documents/{doc_id}",
        document_id=doc_id,
        details=f"Updated document metadata/file for '{title}'"
    )

    flash('Document updated successfully.', 'success')
    return redirect(url_for('documents.view_document', doc_id=doc_id))


@documents_bp.route('/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    """
    Delete document:
    - Strictly reserved for the document owner.
    - Prevents IDOR/unauthorized deletion attempts.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'delete')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}/delete",
            document_id=doc_id,
            details=f"Unauthorized delete attempt: {message}"
        )
        abort(status_code, description=message)

    conn = get_db()
    cursor = conn.cursor()

    # Remove file from storage
    storage_folder = Path(current_app.config['STORAGE_FOLDER'])
    file_path = storage_folder / doc['stored_filename']
    if file_path.exists():
        try:
            os.remove(file_path)
        except OSError:
            pass

    # Delete record (foreign key cascade deletes permissions)
    cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()

    log_audit(
        action='DOC_DELETE',
        status='SUCCESS',
        resource=f"/documents/{doc_id}",
        document_id=doc_id,
        details=f"Deleted document '{doc['title']}' (original: {doc['original_filename']})"
    )

    flash(f"Document '{doc['title']}' was deleted.", 'info')
    return redirect(url_for('documents.list_documents'))


@documents_bp.route('/<int:doc_id>/permissions/grant', methods=['POST'])
@login_required
def grant_permission(doc_id):
    """
    Grant read or edit permission to a named user:
    - Only document owner can grant permissions.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'manage_permissions')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}/permissions/grant",
            document_id=doc_id,
            details=f"Unauthorized grant attempt: {message}"
        )
        abort(status_code, description=message)

    grantee_email = request.form.get('email', '').strip().lower()
    grantee_id_str = request.form.get('user_id', '').strip()
    permission_level = request.form.get('permission_level', 'read').strip()

    if permission_level not in ('read', 'edit'):
        flash('Invalid permission level specified.', 'danger')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    conn = get_db()
    cursor = conn.cursor()

    # Look up grantee
    grantee = None
    if grantee_id_str:
        cursor.execute("SELECT id, email, username FROM users WHERE id = ?", (grantee_id_str,))
        grantee = cursor.fetchone()
    elif grantee_email:
        cursor.execute("SELECT id, email, username FROM users WHERE email = ?", (grantee_email,))
        grantee = cursor.fetchone()

    if not grantee:
        flash('Specified user not found.', 'danger')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    if grantee['id'] == user_id:
        flash('You cannot grant permissions to yourself; you are the owner.', 'warning')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    # Insert or update permission
    cursor.execute(
        """
        INSERT INTO document_permissions (document_id, user_id, permission_level, granted_by)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(document_id, user_id) DO UPDATE SET
            permission_level = excluded.permission_level,
            granted_by = excluded.granted_by,
            created_at = CURRENT_TIMESTAMP
        """,
        (doc_id, grantee['id'], permission_level, user_id)
    )
    conn.commit()

    log_audit(
        action='PERM_GRANT',
        status='SUCCESS',
        resource=f"/documents/{doc_id}/permissions",
        document_id=doc_id,
        details=f"Granted '{permission_level}' permission to user {grantee['email']} ({grantee['username']})"
    )

    flash(f"Granted {permission_level.upper()} permission to {grantee['username']}.", 'success')
    return redirect(url_for('documents.view_document', doc_id=doc_id))


@documents_bp.route('/<int:doc_id>/permissions/revoke', methods=['POST'])
@login_required
def revoke_permission(doc_id):
    """
    Revoke permission from a named user:
    - Only document owner can revoke permissions.
    - Revocation blocks subsequent requests immediately on the server.
    """
    user_id = session['user_id']
    user_role = session.get('role')

    allowed, status_code, message, doc = check_document_permission(doc_id, user_id, user_role, 'manage_permissions')
    if not allowed:
        log_audit(
            action='ACCESS_DENIED',
            status='DENIED',
            resource=f"/documents/{doc_id}/permissions/revoke",
            document_id=doc_id,
            details=f"Unauthorized revoke attempt: {message}"
        )
        abort(status_code, description=message)

    target_user_id = request.form.get('target_user_id')
    if not target_user_id:
        flash('Target user must be specified.', 'danger')
        return redirect(url_for('documents.view_document', doc_id=doc_id))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT email, username FROM users WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()

    cursor.execute(
        "DELETE FROM document_permissions WHERE document_id = ? AND user_id = ?",
        (doc_id, target_user_id)
    )
    conn.commit()

    target_name = target_user['username'] if target_user else f"User {target_user_id}"
    log_audit(
        action='PERM_REVOKE',
        status='SUCCESS',
        resource=f"/documents/{doc_id}/permissions",
        document_id=doc_id,
        details=f"Revoked permission for {target_name} on document '{doc['title']}'"
    )

    flash(f"Revoked permission for {target_name}. Access blocked immediately.", 'info')
    return redirect(url_for('documents.view_document', doc_id=doc_id))
