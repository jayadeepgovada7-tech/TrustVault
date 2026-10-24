import pytest
import os
import tempfile
import shutil
from app import create_app
from app.database import init_db, seed_db

def test_csrf_protection_blocks_state_change_without_token():
    """Verify that state-changing requests without CSRF token are rejected with 400."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, 'test_csrf.db')
    storage_folder = os.path.join(temp_dir, 'vault_storage')
    os.makedirs(storage_folder, exist_ok=True)

    test_config = {
        'TESTING': True,
        'DATABASE_PATH': db_path,
        'STORAGE_FOLDER': storage_folder,
        'SECRET_KEY': 'csrf-test-secret-key',
        'WTF_CSRF_ENABLED': True, # CSRF strictly enabled
    }

    app = create_app(test_config)
    with app.app_context():
        init_db(db_path)
        seed_db(db_path)

    client = app.test_client()

    # Step 1: Login without CSRF token: must be rejected with 400
    resp = client.post('/auth/login', data={
        'email': 'owner@trustvault.local',
        'password': 'Owner@TrustVault2026!'
    })
    assert resp.status_code == 400
    assert b"CSRF validation failed" in resp.data

    # Step 2: GET login page to obtain a session and valid CSRF token
    get_resp = client.get('/auth/login')
    assert get_resp.status_code == 200

    # Extract session token
    with client.session_transaction() as sess:
        valid_csrf_token = sess.get('_csrf_token')

    assert valid_csrf_token is not None

    # Step 3: POST with valid CSRF token succeeds
    post_resp = client.post('/auth/login', data={
        'email': 'owner@trustvault.local',
        'password': 'Owner@TrustVault2026!',
        'csrf_token': valid_csrf_token
    }, follow_redirects=True)
    assert post_resp.status_code == 200
    # Step 4: POST logout without CSRF token: rejected with 400
    logout_no_csrf = client.post('/auth/logout')
    assert logout_no_csrf.status_code == 400
    assert b"CSRF validation failed" in logout_no_csrf.data

    # Step 5: POST logout with valid CSRF token: succeeds
    with client.session_transaction() as sess:
        current_csrf = sess.get('_csrf_token')

    logout_resp = client.post('/auth/logout', data={'csrf_token': current_csrf}, follow_redirects=True)
    assert logout_resp.status_code == 200
    assert b"logged out" in logout_resp.data.lower()

    shutil.rmtree(temp_dir, ignore_errors=True)
