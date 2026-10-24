import os
import sqlite3
from flask import g, current_app
from werkzeug.security import generate_password_hash
from pathlib import Path

def get_db(db_path=None):
    """
    Get a database connection. If in a Flask request context, reuse connection in g.
    Enforces foreign keys and returns sqlite3.Row for safe named access.
    """
    if db_path is None:
        if current_app:
            db_path = current_app.config['DATABASE_PATH']
        else:
            from app.config import Config
            db_path = Config.DATABASE_PATH

    if current_app and 'db' in g:
        return g.db

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Critical security control: enforce foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON;")
    
    if current_app:
        g.db = conn

    return conn

def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(db_path=None):
    """Execute schema.sql to initialize all tables and triggers."""
    conn = get_db(db_path)
    schema_path = Path(__file__).resolve().parent.parent / 'schema.sql'
    with open(schema_path, 'r', encoding='utf-8') as f:
        conn.executescript(f.read())
    conn.commit()
    return conn

def seed_db(db_path=None):
    """
    Seed initial test accounts for local development and verification:
    - administrator: admin@trustvault.local
    - document_owner: owner@trustvault.local
    - viewer: viewer@trustvault.local
    - otherowner: otherowner@trustvault.local (for cross-user boundary testing)
    """
    conn = get_db(db_path)
    cursor = conn.cursor()

    seed_users = [
        {
            'email': 'admin@trustvault.local',
            'username': 'admin',
            'password': 'Admin@TrustVault2026!',
            'role': 'administrator'
        },
        {
            'email': 'owner@trustvault.local',
            'username': 'owner_alice',
            'password': 'Owner@TrustVault2026!',
            'role': 'document_owner'
        },
        {
            'email': 'viewer@trustvault.local',
            'username': 'viewer_bob',
            'password': 'Viewer@TrustVault2026!',
            'role': 'viewer'
        },
        {
            'email': 'otherowner@trustvault.local',
            'username': 'owner_charlie',
            'password': 'Other@TrustVault2026!',
            'role': 'document_owner'
        }
    ]

    for user in seed_users:
        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user['email'],))
        existing = cursor.fetchone()
        if not existing:
            hashed_pw = generate_password_hash(user['password'], method='scrypt')
            cursor.execute(
                """
                INSERT INTO users (email, username, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (user['email'], user['username'], hashed_pw, user['role'])
            )

    conn.commit()

    # Log initial seed event to audit log if empty
    cursor.execute("SELECT COUNT(*) as count FROM audit_logs")
    if cursor.fetchone()['count'] == 0:
        cursor.execute(
            """
            INSERT INTO audit_logs (timestamp, user_id, user_email, action, resource, status, ip_address, details)
            VALUES (CURRENT_TIMESTAMP, NULL, 'system', 'SYSTEM_INITIALIZATION', 'DATABASE', 'SUCCESS', '127.0.0.1', 'Database initialized and seeded with development accounts')
            """
        )
        conn.commit()
