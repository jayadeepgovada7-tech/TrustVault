import sqlite3
import pytest
from app.database import get_db
from tests.test_security import upload_sample_doc

def test_audit_logs_record_actions(app_instance, owner_client, other_owner_client):
    """Verify that all protected operations and denied attempts produce audit log entries."""
    # Upload document
    doc_id = upload_sample_doc(owner_client, title="Audit Verified Doc")

    # Read document
    owner_client.get(f'/documents/{doc_id}')

    # Download document
    owner_client.get(f'/documents/{doc_id}/download')

    # Edit document
    owner_client.post(f'/documents/{doc_id}/edit', data={'title': 'Audit Edited Title'})

    # Grant permission
    owner_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'viewer@trustvault.local',
        'permission_level': 'read'
    })

    # Revoke permission
    owner_client.post(f'/documents/{doc_id}/permissions/revoke', data={
        'target_user_id': 3
    })

    # Denied access attempt (other owner IDOR attempt)
    other_owner_client.get(f'/documents/{doc_id}/download')

    # Verify audit log entries in database
    with app_instance.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT action, status, document_id FROM audit_logs ORDER BY id ASC")
        logs = cursor.fetchall()

        actions = [log['action'] for log in logs]
        statuses = [log['status'] for log in logs]

        assert 'DOC_UPLOAD' in actions
        assert 'DOC_READ' in actions
        assert 'DOC_DOWNLOAD' in actions
        assert 'DOC_EDIT' in actions
        assert 'PERM_GRANT' in actions
        assert 'PERM_REVOKE' in actions
        assert 'ACCESS_DENIED' in actions
        assert 'DENIED' in statuses


def test_append_only_database_triggers(app_instance):
    """
    Test defense-in-depth:
    SQLite database triggers must fail any UPDATE or DELETE statement on audit_logs.
    """
    with app_instance.app_context():
        conn = get_db()
        cursor = conn.cursor()

        # Insert a test log entry
        cursor.execute(
            """
            INSERT INTO audit_logs (user_id, user_email, action, status, details)
            VALUES (1, 'admin@trustvault.local', 'TEST_EVENT', 'SUCCESS', 'Initial entry')
            """
        )
        conn.commit()
        log_id = cursor.lastrowid

        # Attempt to UPDATE audit log: must fail via trigger
        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            cursor.execute("UPDATE audit_logs SET details = 'Tampered log content' WHERE id = ?", (log_id,))
            conn.commit()
        assert "Audit log is append-only" in str(exc_info.value)

        # Attempt to DELETE from audit log: must fail via trigger
        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            cursor.execute("DELETE FROM audit_logs WHERE id = ?", (log_id,))
            conn.commit()
        assert "Audit log is append-only" in str(exc_info.value)
