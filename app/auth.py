import functools
import re
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash, generate_password_hash
from app.database import get_db
from app.audit import log_audit
from app.security import generate_csrf_token

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(view):
    """
    Decorator ensuring that only authenticated sessions with active accounts can access the view.
    Enforces immediate session revocation if an account is deactivated.
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get('user_id')
        if not user_id:
            log_audit(
                action='ACCESS_DENIED',
                status='DENIED',
                resource=request.path,
                details='Unauthenticated access attempt redirected to login'
            )
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.path))

        # Enforce immediate account deactivation check on all protected requests
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, is_active, role, email FROM users WHERE id = ?", (user_id,))
        active_user = cursor.fetchone()

        if not active_user or not active_user['is_active']:
            user_email = session.get('user_email', 'unknown')
            log_audit(
                action='ACCESS_DENIED',
                status='DENIED',
                resource=request.path,
                user_id=user_id,
                user_email=user_email,
                details='Active session rejected immediately: user account is deactivated'
            )
            session.clear()
            flash('Your account has been deactivated. Access revoked immediately.', 'danger')
            abort(403, description="Forbidden: Account is inactive or disabled.")

        # Keep session role synchronized with database authority
        session['role'] = active_user['role']
        return view(**kwargs)
    return wrapped_view

def roles_required(*allowed_roles):
    """Decorator ensuring the authenticated user possesses one of the authorized roles."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped_view(**kwargs):
            if 'user_id' not in session:
                return redirect(url_for('auth.login', next=request.path))
            user_role = session.get('role')
            if user_role not in allowed_roles:
                log_audit(
                    action='PRIVILEGE_ESCALATION_ATTEMPT',
                    status='DENIED',
                    resource=request.path,
                    details=f"User role '{user_role}' denied access. Required: {allowed_roles}"
                )
                abort(403, description="Forbidden: Insufficient privileges for this operation.")
            return view(**kwargs)
        return wrapped_view
    return decorator

def admin_required(view):
    """Shorthand decorator for administrator-only routes."""
    return roles_required('administrator')(view)

def validate_password_strength(password):
    """Enforce minimum 8 characters, at least one uppercase, lowercase, digit, and special char."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include at least one special character (!@#$%^&*...)."
    return True, None

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return render_template('login.html'), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            if not user['is_active']:
                log_audit(
                    action='AUTH_LOGIN_FAILED',
                    status='DENIED',
                    resource='/auth/login',
                    user_email=email,
                    details='Account is inactive/disabled'
                )
                flash('Your account has been deactivated. Please contact an administrator.', 'danger')
                return render_template('login.html'), 403

            # Session Fixation Defense: Clear any prior session state before assigning identity
            session.clear()
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['username'] = user['username']
            session['role'] = user['role']
            generate_csrf_token()

            log_audit(
                action='AUTH_LOGIN_SUCCESS',
                status='SUCCESS',
                resource='/auth/login',
                details=f"User logged in successfully with role '{user['role']}'"
            )

            # Redirect safely to next or dashboard
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                return redirect(next_url)
            
            if user['role'] == 'administrator':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('documents.list_documents'))
        else:
            # Generic error message to prevent account enumeration
            log_audit(
                action='AUTH_LOGIN_FAILED',
                status='DENIED',
                resource='/auth/login',
                user_email=email,
                details='Invalid credentials supplied'
            )
            flash('Invalid email or password.', 'danger')
            return render_template('login.html'), 401

    return render_template('login.html')

@auth_bp.route('/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    
    if user_id:
        log_audit(
            action='AUTH_LOGOUT',
            status='SUCCESS',
            resource='/auth/logout',
            user_id=user_id,
            user_email=user_email,
            details='User logged out'
        )
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        requested_role = request.form.get('role', 'viewer').strip()

        # Security check: never allow public registration of 'administrator' role!
        if requested_role not in ('document_owner', 'viewer'):
            log_audit(
                action='PRIVILEGE_ESCALATION_ATTEMPT',
                status='DENIED',
                resource='/auth/register',
                details=f"Attempted registration with prohibited role '{requested_role}'"
            )
            flash('Invalid role selected.', 'danger')
            return render_template('register.html'), 400

        if not email or not username or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html'), 400

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html'), 400

        is_strong, err_msg = validate_password_strength(password)
        if not is_strong:
            flash(err_msg, 'danger')
            return render_template('register.html'), 400

        conn = get_db()
        cursor = conn.cursor()
        
        # Check uniqueness
        cursor.execute("SELECT id FROM users WHERE email = ? OR username = ?", (email, username))
        if cursor.fetchone():
            flash('An account with this email or username already exists.', 'danger')
            return render_template('register.html'), 400

        password_hash = generate_password_hash(password, method='scrypt')
        cursor.execute(
            """
            INSERT INTO users (email, username, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (email, username, password_hash, requested_role)
        )
        conn.commit()

        log_audit(
            action='AUTH_REGISTER',
            status='SUCCESS',
            resource='/auth/register',
            user_email=email,
            details=f"New user registered with role '{requested_role}'"
        )
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')
