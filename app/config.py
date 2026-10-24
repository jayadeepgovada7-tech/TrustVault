import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INSECURE_SECRETS = {
    'dev-secret-key-trustvault-snovasys-2026-fresher-challenge-keep-secret',
    'secret', 'changeme', 'password', '123456', 'admin', 'test', 'default'
}

def get_secret_key():
    """
    Retrieve and validate application SECRET_KEY.
    In production environments, missing or insecure secrets fail immediately.
    """
    env = os.environ.get('FLASK_ENV', os.environ.get('TRUSTVAULT_ENV', 'development')).lower()
    raw_secret = os.environ.get('SECRET_KEY')
    is_production = env in ('production', 'prod')

    if is_production:
        if not raw_secret:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY environment variable is missing. "
                "Production deployment requires an explicitly configured, high-entropy secret key."
            )
        if len(raw_secret) < 32:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY must be at least 32 characters in production."
            )
        if raw_secret.lower() in INSECURE_SECRETS:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Prohibited insecure placeholder detected in SECRET_KEY."
            )
        return raw_secret

    # Development and test fallback
    return raw_secret or 'dev-secret-key-trustvault-snovasys-2026-fresher-challenge-keep-secret'

class Config:
    # Security: Secret key for session signing and CSRF tokens
    SECRET_KEY = get_secret_key()
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_PATH', str(BASE_DIR / 'trustvault.db'))
    
    # Secure storage directory - OUTSIDE public/static directory
    STORAGE_FOLDER = os.environ.get('STORAGE_FOLDER', str(BASE_DIR / 'vault_storage'))
    
    # File upload limits & validation
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'csv', 'docx', 'xlsx'}
    
    # Session security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('TRUSTVAULT_SECURE_COOKIE', 'False').lower() in ('true', '1')
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Application environment
    ENV = os.environ.get('FLASK_ENV', os.environ.get('TRUSTVAULT_ENV', 'development'))
    DEBUG = False  # Deny debug mode by default in production; explicit toggle only
