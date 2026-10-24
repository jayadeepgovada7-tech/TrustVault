import io
import pytest
from app.database import get_db
from tests.test_security import upload_sample_doc

def test_grant_read_permission(owner_client, viewer_client):
    """Test owner granting read-only permission to a viewer."""
    doc_id = upload_sample_doc(owner_client, title="Q1 Report")

    # Viewer initially cannot view or download
    resp = viewer_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 403

    # Owner grants 'read' permission to viewer
    resp = owner_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'viewer@trustvault.local',
        'permission_level': 'read'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Granted READ permission" in resp.data

    # Viewer can now view details
    resp = viewer_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 200
    assert b"Q1 Report" in resp.data

    # Viewer can now download
    resp = viewer_client.get(f'/documents/{doc_id}/download')
    assert resp.status_code == 200
    assert resp.data == b"%PDF-1.4 sample pdf content"

    # Viewer CANNOT edit with read-only permission
    resp = viewer_client.post(f'/documents/{doc_id}/edit', data={'title': 'Altered Title'})
    assert resp.status_code == 403


def test_grant_edit_permission(owner_client, viewer_client):
    """Test owner granting 'edit' permission to a viewer."""
    doc_id = upload_sample_doc(owner_client, title="Editable Strategy Doc")

    # Owner grants 'edit' permission to viewer
    resp = owner_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'viewer@trustvault.local',
        'permission_level': 'edit'
    }, follow_redirects=True)
    assert resp.status_code == 200

    # Viewer can now edit metadata
    resp = viewer_client.post(f'/documents/{doc_id}/edit', data={
        'title': 'Collaboratively Edited Title',
        'description': 'Updated by viewer with edit permission',
        'category': 'Strategy',
        'tags': 'updated'
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Collaboratively Edited Title" in resp.data

    # But viewer STILL CANNOT delete document (delete is strictly owner only!)
    resp = viewer_client.post(f'/documents/{doc_id}/delete')
    assert resp.status_code == 403

    # And viewer CANNOT grant permissions to third parties
    resp = viewer_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'otherowner@trustvault.local',
        'permission_level': 'read'
    })
    assert resp.status_code == 403


def test_immediate_revocation_blocks_subsequent_requests(owner_client, viewer_client):
    """
    Critical requirement:
    Revocation must block subsequent requests immediately.
    """
    doc_id = upload_sample_doc(owner_client, title="Immediate Revocation Test")

    # 1. Grant read access to viewer
    owner_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'viewer@trustvault.local',
        'permission_level': 'read'
    })

    # Verify viewer has access
    resp = viewer_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 200

    # 2. Owner immediately revokes access
    # Viewer ID is 3 (viewer_bob)
    resp = owner_client.post(f'/documents/{doc_id}/permissions/revoke', data={
        'target_user_id': 3
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Access blocked immediately" in resp.data

    # 3. Viewer attempts subsequent view -> IMMEDIATELY BLOCKED (403)
    resp = viewer_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 403

    # 4. Viewer attempts subsequent download -> IMMEDIATELY BLOCKED (403)
    resp = viewer_client.get(f'/documents/{doc_id}/download')
    assert resp.status_code == 403


def test_search_filters_owner_and_date(owner_client, other_owner_client):
    """Test searching and filtering documents by owner and date range."""
    # 1. Alice uploads doc
    alice_doc = upload_sample_doc(owner_client, title="Alice Financial Q3")

    # 2. Charlie uploads doc
    charlie_doc = upload_sample_doc(other_owner_client, title="Charlie Tech Blueprint")

    # 3. Alice searches with owner=owner_alice -> finds Alice Financial Q3
    resp = owner_client.get('/documents/?owner=alice')
    assert resp.status_code == 200
    assert b"Alice Financial Q3" in resp.data

    # 4. Alice searches with owner=charlie -> returns 0 documents because Charlie hasn't granted Alice access
    resp = owner_client.get('/documents/?owner=charlie')
    assert resp.status_code == 200
    assert b"Charlie Tech Blueprint" not in resp.data

    # 5. Charlie grants Alice read access to his blueprint
    other_owner_client.post(f'/documents/{charlie_doc}/permissions/grant', data={
        'email': 'owner@trustvault.local',
        'permission_level': 'read'
    })

    # Now Alice searches with owner=charlie -> Charlie Tech Blueprint is visible!
    resp = owner_client.get('/documents/?owner=charlie')
    assert resp.status_code == 200
    assert b"Charlie Tech Blueprint" in resp.data

    # 6. Date filtering: valid date range matching today's upload
    import datetime
    today = datetime.date.today().isoformat()
    resp = owner_client.get(f'/documents/?date_from={today}&date_to={today}')
    assert resp.status_code == 200
    assert b"Alice Financial Q3" in resp.data

    # 7. Date filtering: past or future date outside range
    resp = owner_client.get('/documents/?date_from=2020-01-01&date_to=2020-01-02')
    assert resp.status_code == 200
    assert b"No Accessible Documents Found" in resp.data

