import os
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, session, request
from app.config import Config
from app.database import close_db, init_db, seed_db
from app.security import generate_csrf_token, validate_csrf
from app.auth import auth_bp
from app.documents import documents_bp
from app.admin import admin_bp

def create_app(test_config=None):
    """
    Application factory pattern for TrustVault.
    Initializes configuration, security middlewares, blueprints, and error handlers.
    """
    app = Flask(__name__, instance_relative_config=True)
    
    # Load configuration
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    # Ensure secure vault storage folder exists
    storage_folder = Path(app.config['STORAGE_FOLDER'])
    storage_folder.mkdir(parents=True, exist_ok=True)

    # Register database teardown
    app.teardown_appcontext(close_db)

    # Security: Apply CSRF validation before every request
    @app.before_request
    def enforce_csrf():
        # Exempt static assets and test environments if disabled
        if request.endpoint and 'static' in request.endpoint:
            return
        if app.config.get('WTF_CSRF_ENABLED', True) is False:
            return
        validate_csrf()

    # Security: Set strict HTTP defense headers on every response
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        # Modern Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp
        return response

    # Template context processor for security helpers
    @app.context_processor
    def inject_security_helpers():
        return {
            'csrf_token': generate_csrf_token,
            'current_user': {
                'id': session.get('user_id'),
                'email': session.get('user_email'),
                'username': session.get('username'),
                'role': session.get('role'),
                'is_authenticated': 'user_id' in session
            }
        }

    # Custom Error Handlers (avoid revealing internal stack traces)
    @app.errorhandler(400)
    def handle_bad_request(e):
        return render_template('error.html', code=400, title="Bad Request", message=str(e.description)), 400

    @app.errorhandler(401)
    def handle_unauthorized(e):
        return render_template('error.html', code=401, title="Unauthorized", message=str(e.description)), 401

    @app.errorhandler(403)
    def handle_forbidden(e):
        return render_template('error.html', code=403, title="Access Forbidden", message=str(e.description)), 403

    @app.errorhandler(404)
    def handle_not_found(e):
        return render_template('error.html', code=404, title="Page Not Found", message="The requested resource was not found."), 404

    @app.errorhandler(413)
    def handle_large_file(e):
        return render_template('error.html', code=413, title="Payload Too Large", message="File exceeds the maximum allowed size (16MB)."), 413

    @app.errorhandler(500)
    def handle_internal_error(e):
        return render_template('error.html', code=500, title="Internal Server Error", message="An unexpected error occurred. This incident has been logged."), 500

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)

    # Root route
    @app.route('/')
    def index():
        if 'user_id' in session:
            if session.get('role') == 'administrator':
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('documents.list_documents'))
        return redirect(url_for('auth.login'))

    return app
