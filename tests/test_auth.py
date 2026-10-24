import pytest
from flask import session
from app.database import get_db

def test_login_success_all_roles(client):
    """Test successful authentication for all 3 standard seed accounts."""
    # 1. Administrator
    resp = client.post('/auth/login', data={
        'email': 'admin@trustvault.local',
        'password': 'Admin@TrustVault2026!'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Security & Activity Dashboard" in resp.data

    # 2. Document Owner
    resp = client.post('/auth/login', data={
        'email': 'owner@trustvault.local',
        'password': 'Owner@TrustVault2026!'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Document Repository" in resp.data

    # 3. Viewer
    resp = client.post('/auth/login', data={
        'email': 'viewer@trustvault.local',
        'password': 'Viewer@TrustVault2026!'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Document Repository" in resp.data


def test_login_failure_invalid_credentials(client):
    """Ensure invalid credentials return 401 with generic error message to prevent enumeration."""
    # Wrong password
    resp = client.post('/auth/login', data={
        'email': 'owner@trustvault.local',
        'password': 'WrongPassword123!'
    })
    assert resp.status_code == 401
    assert b"Invalid email or password." in resp.data

    # Nonexistent user
    resp = client.post('/auth/login', data={
        'email': 'unknown@example.com',
        'password': 'WrongPassword123!'
    })
    assert resp.status_code == 401
    assert b"Invalid email or password." in resp.data


def test_deactivated_account_blocked(app_instance, client):
    """Ensure deactivated accounts cannot authenticate."""
    with app_instance.app_context():
        conn = get_db()
        conn.execute("UPDATE users SET is_active = 0 WHERE email = 'viewer@trustvault.local'")
        conn.commit()

    resp = client.post('/auth/login', data={
        'email': 'viewer@trustvault.local',
        'password': 'Viewer@TrustVault2026!'
    })
    assert resp.status_code == 403
    assert b"deactivated" in resp.data.lower()


def test_session_cleared_on_login_session_fixation_defense(client):
    """Verify session data is cleared upon authentication to protect against session fixation."""
    with client.session_transaction() as sess:
        sess['attacker_marker'] = 'malicious_pre_auth_token'

    client.post('/auth/login', data={
        'email': 'owner@trustvault.local',
        'password': 'Owner@TrustVault2026!'
    })

    with client.session_transaction() as sess:
        assert 'attacker_marker' not in sess
        assert sess['user_email'] == 'owner@trustvault.local'


def test_registration_validation(client):
    """Test user registration constraints, password complexity, and role restrictions."""
    # 1. Weak password rejected
    resp = client.post('/auth/register', data={
        'username': 'weak_user',
        'email': 'weak@example.com',
        'password': 'weak',
        'confirm_password': 'weak',
        'role': 'viewer'
    })
    assert resp.status_code == 400
    assert b"Password must be at least 8 characters long" in resp.data

    # 2. Privilege Escalation: Public self-registration of 'administrator' role is strictly blocked
    resp = client.post('/auth/register', data={
        'username': 'fake_admin',
        'email': 'fake_admin@example.com',
        'password': 'SecureAdminPass2026!',
        'confirm_password': 'SecureAdminPass2026!',
        'role': 'administrator'
    })
    assert resp.status_code == 400
    assert b"Invalid role selected" in resp.data

    # 3. Valid registration succeeds
    resp = client.post('/auth/register', data={
        'username': 'valid_user',
        'email': 'valid@example.com',
        'password': 'ValidPassword2026!',
        'confirm_password': 'ValidPassword2026!',
        'role': 'document_owner'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Registration successful" in resp.data

    # 4. Duplicate registration rejected
    resp = client.post('/auth/register', data={
        'username': 'valid_user',
        'email': 'valid@example.com',
        'password': 'ValidPassword2026!',
        'confirm_password': 'ValidPassword2026!',
        'role': 'document_owner'
    })
    assert resp.status_code == 400
    assert b"already exists" in resp.data


def test_logout(owner_client):
    """Test that logout is POST-only and terminates the session."""
    # GET request must be rejected with 405 Method Not Allowed
    get_resp = owner_client.get('/auth/logout')
    assert get_resp.status_code == 405

    # POST request succeeds
    resp = owner_client.post('/auth/logout', follow_redirects=True)
    assert resp.status_code == 200
    assert b"logged out" in resp.data.lower()

    # Accessing protected page now redirects to login
    resp = owner_client.get('/documents/')
    assert resp.status_code == 302
    assert '/auth/login' in resp.headers['Location']


def test_production_secret_key_validation(monkeypatch):
    """Verify that in production, missing or weak SECRET_KEY safely raises RuntimeError."""
    from app.config import get_secret_key
    
    # Production without secret key -> raises RuntimeError
    monkeypatch.setenv('FLASK_ENV', 'production')
    monkeypatch.delenv('SECRET_KEY', raising=False)
    with pytest.raises(RuntimeError) as exc:
        get_secret_key()
    assert "SECRET_KEY environment variable is missing" in str(exc.value)

    # Production with short secret key -> raises RuntimeError
    monkeypatch.setenv('SECRET_KEY', 'short_insecure_key')
    with pytest.raises(RuntimeError) as exc:
        get_secret_key()
    assert "must be at least 32 characters" in str(exc.value)

    # Production with insecure default placeholder -> raises RuntimeError
    monkeypatch.setenv('SECRET_KEY', 'dev-secret-key-trustvault-snovasys-2026-fresher-challenge-keep-secret')
    with pytest.raises(RuntimeError) as exc:
        get_secret_key()
    assert "Prohibited insecure placeholder" in str(exc.value)

    # Production with valid high-entropy key -> succeeds
    valid_key = 'a' * 32
    monkeypatch.setenv('SECRET_KEY', valid_key)
    assert get_secret_key() == valid_key


def test_immediate_account_deactivation_for_existing_session(app_instance, viewer_client):
    """Ensure that when an account is deactivated, existing sessions are blocked immediately."""
    # 1. Verify active session can access protected route
    resp = viewer_client.get('/documents/')
    assert resp.status_code == 200

    # 2. Deactivate the user in the database while their session is still active
    with app_instance.app_context():
        conn = get_db()
        conn.execute("UPDATE users SET is_active = 0 WHERE email = 'viewer@trustvault.local'")
        conn.commit()

    # 3. Subsequent request by the same session must be blocked immediately with 403 Forbidden
    resp = viewer_client.get('/documents/')
    assert resp.status_code == 403
    assert b"deactivated" in resp.data.lower() or b"inactive" in resp.data.lower()

    # 4. Session should have been cleared
    with viewer_client.session_transaction() as sess:
        assert 'user_id' not in sess

