import os
import tempfile
import shutil
import pytest
from pathlib import Path
from app import create_app
from app.database import init_db, seed_db, get_db

@pytest.fixture
def app_instance():
    """Create and configure a new Flask application instance for each test suite."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, 'test_vault.db')
    storage_folder = os.path.join(temp_dir, 'vault_storage')
    os.makedirs(storage_folder, exist_ok=True)

    test_config = {
        'TESTING': True,
        'DATABASE_PATH': db_path,
        'STORAGE_FOLDER': storage_folder,
        'SECRET_KEY': 'test-secret-key-trustvault',
        'WTF_CSRF_ENABLED': False, # Disabled globally for unit testing except dedicated CSRF tests
        'SESSION_COOKIE_SECURE': False,
    }

    app = create_app(test_config)

    with app.app_context():
        init_db(db_path)
        seed_db(db_path)

    yield app

    # Cleanup temp directory
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def client(app_instance):
    """Test client for issuing HTTP requests."""
    return app_instance.test_client()

@pytest.fixture
def runner(app_instance):
    """CLI runner for tests."""
    return app_instance.test_cli_runner()

def login_user(client, email, password):
    """Helper to authenticate a test user via session."""
    return client.post('/auth/login', data={'email': email, 'password': password}, follow_redirects=True)

@pytest.fixture
def admin_client(app_instance):
    """Client authenticated as administrator."""
    c = app_instance.test_client()
    login_user(c, 'admin@trustvault.local', 'Admin@TrustVault2026!')
    return c

@pytest.fixture
def owner_client(app_instance):
    """Client authenticated as primary document owner (Alice)."""
    c = app_instance.test_client()
    login_user(c, 'owner@trustvault.local', 'Owner@TrustVault2026!')
    return c

@pytest.fixture
def other_owner_client(app_instance):
    """Client authenticated as secondary document owner (Charlie)."""
    c = app_instance.test_client()
    login_user(c, 'otherowner@trustvault.local', 'Other@TrustVault2026!')
    return c

@pytest.fixture
def viewer_client(app_instance):
    """Client authenticated as viewer (Bob)."""
    c = app_instance.test_client()
    login_user(c, 'viewer@trustvault.local', 'Viewer@TrustVault2026!')
    return c
