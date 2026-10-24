import os
from pathlib import Path

from app import create_app
from app.database import init_db, seed_db

app = create_app()


def bootstrap():
    """Initialize the database for local runs and WSGI deployments."""
    with app.app_context():
        db_path = Path(app.config["DATABASE_PATH"])
        needs_init = not db_path.exists()

        if not needs_init:
            # Handle an existing but empty database file safely.
            import sqlite3
            try:
                with sqlite3.connect(str(db_path)) as conn:
                    conn.execute("SELECT 1 FROM users LIMIT 1")
            except sqlite3.OperationalError:
                needs_init = True

        if needs_init:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            init_db(str(db_path))

        # Seed demo accounts locally by default. Production seeding is opt-in
        # because the demo credentials are intentionally predictable.
        env = str(app.config.get("ENV", "development")).lower()
        is_production = env in ("production", "prod")
        seed_enabled = os.environ.get("TRUSTVAULT_SEED_DEMO_ACCOUNTS", "").lower() in ("1", "true", "yes")
        if not is_production or seed_enabled:
            seed_db(str(db_path))


# Run during module import too, so Gunicorn deployments initialize correctly.
bootstrap()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Trust vault on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
