from flask import Blueprint, render_template, request, session, flash, redirect, url_for
from app.database import get_db
from app.auth import login_required, admin_required
from app.audit import log_audit

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/', methods=['GET'])
@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@admin_required
def dashboard():
    """
    Administrator Activity Dashboard:
    - Displays overall system security posture
    - Aggregated metrics (total documents, storage volume, security incidents/denied attempts)
    - Filterable append-only audit trail
    - Registered user overview
    """
    conn = get_db()
    cursor = conn.cursor()

    # Filter parameters for audit log
    action_filter = request.args.get('action', '').strip()
    status_filter = request.args.get('status', '').strip()
    email_filter = request.args.get('email', '').strip()

    # 1. System Statistics
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) as count, COALESCE(SUM(file_size), 0) as total_bytes FROM documents")
    doc_stats = cursor.fetchone()
    total_documents = doc_stats['count']
    total_storage_bytes = doc_stats['total_bytes']

    cursor.execute("SELECT COUNT(*) as count FROM audit_logs")
    total_audit_events = cursor.fetchone()['count']

    cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE status = 'DENIED'")
    total_denied_events = cursor.fetchone()['count']

    # 2. User role breakdown
    cursor.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
    role_counts = {row['role']: row['count'] for row in cursor.fetchall()}

    # 3. Recent Denied / Security Incidents (Top Alerts)
    cursor.execute(
        """
        SELECT * FROM audit_logs 
        WHERE status = 'DENIED'
        ORDER BY timestamp DESC
        LIMIT 10
        """
    )
    security_alerts = cursor.fetchall()

    # 4. Filterable Audit Log
    base_audit_sql = "SELECT * FROM audit_logs"
    conditions = []
    params = []

    if action_filter:
        conditions.append("action = ?")
        params.append(action_filter)
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)
    if email_filter:
        conditions.append("user_email LIKE ?")
        params.append(f"%{email_filter}%")

    if conditions:
        audit_sql = base_audit_sql + " WHERE " + " AND ".join(conditions) + " ORDER BY timestamp DESC, id DESC LIMIT 100"
    else:
        audit_sql = base_audit_sql + " ORDER BY timestamp DESC, id DESC LIMIT 100"

    cursor.execute(audit_sql, params)
    audit_logs = cursor.fetchall()

    # Get distinct action types for filter dropdown
    cursor.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action ASC")
    distinct_actions = [row['action'] for row in cursor.fetchall()]

    # 5. User list
    cursor.execute(
        """
        SELECT u.id, u.email, u.username, u.role, u.is_active, u.created_at,
               (SELECT COUNT(*) FROM documents WHERE owner_id = u.id) as doc_count
        FROM users u
        ORDER BY u.created_at DESC
        """
    )
    all_users = cursor.fetchall()

    return render_template(
        'admin.html',
        total_users=total_users,
        total_documents=total_documents,
        total_storage_bytes=total_storage_bytes,
        total_audit_events=total_audit_events,
        total_denied_events=total_denied_events,
        role_counts=role_counts,
        security_alerts=security_alerts,
        audit_logs=audit_logs,
        distinct_actions=distinct_actions,
        action_filter=action_filter,
        status_filter=status_filter,
        email_filter=email_filter,
        all_users=all_users
    )

@admin_bp.route('/users/<int:target_user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(target_user_id):
    """Admin feature: deactivate or reactivate user accounts."""
    if target_user_id == session['user_id']:
        flash('You cannot deactivate your own administrative account.', 'warning')
        return redirect(url_for('admin.dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active, email FROM users WHERE id = ?", (target_user_id,))
    target = cursor.fetchone()

    if not target:
        flash('User not found.', 'danger')
        return redirect(url_for('admin.dashboard'))

    new_status = 0 if target['is_active'] else 1
    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, target_user_id))
    conn.commit()

    action_label = "Deactivated" if new_status == 0 else "Reactivated"
    log_audit(
        action='USER_STATUS_CHANGE',
        status='SUCCESS',
        resource=f"/admin/users/{target_user_id}",
        details=f"{action_label} user account: {target['email']}"
    )

    flash(f"User {target['email']} has been {action_label.lower()}.", 'info')
    return redirect(url_for('admin.dashboard'))
