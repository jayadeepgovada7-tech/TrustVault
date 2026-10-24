import io
import pytest
from app.database import get_db

def upload_sample_doc(client, title="Alice Secret Doc", filename="secret.pdf", content=b"%PDF-1.4 sample pdf content"):
    """Helper to upload a valid document via client."""
    data = {
        'title': title,
        'category': 'Confidential',
        'tags': 'finance,audit',
        'description': 'Proprietary document for Alice',
        'file': (io.BytesIO(content), filename)
    }
    resp = client.post('/documents/upload', data=data, content_type='multipart/form-data', follow_redirects=False)
    assert resp.status_code == 302
    doc_id = int(resp.headers['Location'].split('/')[-1])
    return doc_id


def test_unauthenticated_access_denied(client):
    """Ensure unauthenticated access to protected endpoints is strictly denied by default."""
    endpoints = [
        '/documents/',
        '/documents/upload',
        '/documents/1',
        '/documents/1/download',
        '/admin/dashboard'
    ]
    for ep in endpoints:
        resp = client.get(ep)
        # Should redirect to login (302) or return 401/403
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


def test_idor_cross_user_document_manipulation(owner_client, other_owner_client):
    """
    Test IDOR / BOLA defense:
    Alice (owner) uploads a document. Charlie (other_owner) tries to:
    - View document details
    - Download document file
    - Edit document metadata
    - Delete document
    - Grant permissions on Alice's document
    - Revoke permissions on Alice's document
    ALL must return 403 Forbidden!
    """
    alice_doc_id = upload_sample_doc(owner_client, title="Alice Private Budget")

    # 1. Charlie tries to view Alice's document details
    resp = other_owner_client.get(f'/documents/{alice_doc_id}')
    assert resp.status_code == 403

    # 2. Charlie tries to download Alice's document directly
    resp = other_owner_client.get(f'/documents/{alice_doc_id}/download')
    assert resp.status_code == 403

    # 3. Charlie tries to edit Alice's document
    resp = other_owner_client.post(f'/documents/{alice_doc_id}/edit', data={
        'title': 'Hacked Title by Charlie',
        'description': 'Overwritten description'
    })
    assert resp.status_code == 403

    # 4. Charlie tries to delete Alice's document
    resp = other_owner_client.post(f'/documents/{alice_doc_id}/delete')
    assert resp.status_code == 403

    # 5. Charlie tries to grant permissions on Alice's document
    resp = other_owner_client.post(f'/documents/{alice_doc_id}/permissions/grant', data={
        'email': 'viewer@trustvault.local',
        'permission_level': 'edit'
    })
    assert resp.status_code == 403

    # 6. Charlie tries to revoke permissions on Alice's document
    resp = other_owner_client.post(f'/documents/{alice_doc_id}/permissions/revoke', data={
        'target_user_id': 3
    })
    assert resp.status_code == 403


def test_direct_download_unauthorized(owner_client, viewer_client):
    """Ensure non-authorized viewers cannot directly download documents by guessing document IDs."""
    doc_id = upload_sample_doc(owner_client, title="Alice Secret Project")

    # Viewer without permission attempts download
    resp = viewer_client.get(f'/documents/{doc_id}/download')
    assert resp.status_code == 403
    assert b"Access denied" in resp.data or b"Forbidden" in resp.data


def test_privilege_escalation_blocked(owner_client, viewer_client):
    """
    Test privilege escalation defenses:
    - Viewer and Owner cannot access Admin Dashboard
    - Viewer cannot upload documents
    - Viewer cannot toggle user active statuses
    """
    # 1. Owner attempts to access admin dashboard
    resp = owner_client.get('/admin/dashboard')
    assert resp.status_code == 403

    # 2. Viewer attempts to access admin dashboard
    resp = viewer_client.get('/admin/dashboard')
    assert resp.status_code == 403

    # 3. Viewer attempts to access upload form
    resp = viewer_client.get('/documents/upload')
    assert resp.status_code == 403

    # 4. Viewer attempts to submit document upload
    resp = viewer_client.post('/documents/upload', data={
        'title': 'Viewer Document',
        'file': (io.BytesIO(b'%PDF-1.4 test'), 'test.pdf')
    })
    assert resp.status_code == 403

    # 5. Viewer attempts to deactivate admin account
    resp = viewer_client.post('/admin/users/1/toggle-status')
    assert resp.status_code == 403


def test_file_upload_validation_and_magic_bytes(owner_client):
    """
    Test comprehensive file validation:
    - Disallowed extensions rejected
    - Disguised files (wrong magic bytes) rejected
    - Dangerous executable signatures (MZ, ELF) rejected
    - Text files with binary null bytes rejected
    - Empty files rejected
    - Valid files accepted with random UUID storage name
    """
    # 1. Disallowed extension: .exe
    resp = owner_client.post('/documents/upload', data={
        'title': 'Malicious App',
        'file': (io.BytesIO(b'MZfakeexe'), 'malicious.exe')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"is not permitted" in resp.data

    # 2. Disguised executable named .pdf (Magic Byte verification catches this!)
    resp = owner_client.post('/documents/upload', data={
        'title': 'Fake PDF',
        'file': (io.BytesIO(b'MZ\x90\x00\x03\x00\x00\x00this is a windows pe binary disguised as pdf'), 'trojan.pdf')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"prohibited content signature" in resp.data or b"does not match the signature" in resp.data

    # 3. Fake PDF with random text content (fails %PDF- header check)
    resp = owner_client.post('/documents/upload', data={
        'title': 'Text Disguised as PDF',
        'file': (io.BytesIO(b'This is just regular text, not a real PDF structure'), 'not_pdf.pdf')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"does not match the signature for a valid .pdf" in resp.data

    # 4. Text file containing null binary bytes rejected
    resp = owner_client.post('/documents/upload', data={
        'title': 'Corrupted Text File',
        'file': (io.BytesIO(b'Text with a null byte \x00 in the middle'), 'test.txt')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"Text/CSV files cannot contain null binary bytes" in resp.data

    # 5. Empty file rejected
    resp = owner_client.post('/documents/upload', data={
        'title': 'Empty Document',
        'file': (io.BytesIO(b''), 'empty.txt')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"Empty files are not allowed" in resp.data

    # 6. Valid PNG image passes magic bytes check (\x89PNG\r\n\x1a\n)
    valid_png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4'
    resp = owner_client.post('/documents/upload', data={
        'title': 'Valid Architecture Diagram',
        'category': 'Engineering',
        'file': (io.BytesIO(valid_png_header), 'diagram.png')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Valid Architecture Diagram" in resp.data


def test_random_server_generated_storage_filename(app_instance, owner_client):
    """Verify that stored filename is unpredictable random UUID and NOT client-supplied original name."""
    doc_id = upload_sample_doc(owner_client, title="Path Traversal Test", filename="../../../etc_passwd.pdf")

    with app_instance.app_context():
        conn = get_db()
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        
        # Original name is sanitized
        assert "etc_passwd.pdf" in doc['original_filename']
        assert "../" not in doc['original_filename']

        # Stored filename is a random hex string with .pdf extension
        assert doc['stored_filename'].endswith('.pdf')
        assert len(doc['stored_filename']) >= 36  # 32 hex chars + .pdf
        assert "etc_passwd" not in doc['stored_filename']


def create_in_memory_zip(file_map):
    """Helper to construct in-memory zip archives for test fixtures."""
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in file_map.items():
            zf.writestr(filename, content)
    buf.seek(0)
    return buf.getvalue()


def test_office_archive_validation(owner_client):
    """Test strict Office archive validation (DOCX and XLSX)."""
    # 1. Valid DOCX
    valid_docx = create_in_memory_zip({
        '[Content_Types].xml': '<Types></Types>',
        'word/document.xml': '<w:document></w:document>'
    })
    resp = owner_client.post('/documents/upload', data={
        'title': 'Valid Word Document',
        'file': (io.BytesIO(valid_docx), 'report.docx')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Valid Word Document" in resp.data

    # 2. Invalid DOCX missing word/document.xml
    invalid_docx = create_in_memory_zip({
        '[Content_Types].xml': '<Types></Types>',
        'some_other_file.txt': 'hello'
    })
    resp = owner_client.post('/documents/upload', data={
        'title': 'Incomplete Word Document',
        'file': (io.BytesIO(invalid_docx), 'bad.docx')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"missing Word document structures" in resp.data

    # 3. Malicious DOCX with Zip Slip / Path Traversal
    traversal_docx = create_in_memory_zip({
        '[Content_Types].xml': '<Types></Types>',
        'word/document.xml': '<w:document></w:document>',
        '../../evil.bat': 'malicious script'
    })
    resp = owner_client.post('/documents/upload', data={
        'title': 'Zip Slip Docx',
        'file': (io.BytesIO(traversal_docx), 'slip.docx')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"illegal or traversal file paths" in resp.data

    # 4. Malicious DOCX with embedded executable
    exe_docx = create_in_memory_zip({
        '[Content_Types].xml': '<Types></Types>',
        'word/document.xml': '<w:document></w:document>',
        'word/payload.exe': 'fake_binary'
    })
    resp = owner_client.post('/documents/upload', data={
        'title': 'Executable Embedded Docx',
        'file': (io.BytesIO(exe_docx), 'embedded.docx')
    }, content_type='multipart/form-data')
    assert resp.status_code == 400
    assert b"prohibited embedded file type" in resp.data

    # 5. Valid XLSX
    valid_xlsx = create_in_memory_zip({
        '[Content_Types].xml': '<Types></Types>',
        'xl/workbook.xml': '<workbook></workbook>'
    })
    resp = owner_client.post('/documents/upload', data={
        'title': 'Valid Excel Workbook',
        'file': (io.BytesIO(valid_xlsx), 'sheet.xlsx')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Valid Excel Workbook" in resp.data


def test_jpeg_and_csv_uploads(owner_client):
    """Test valid uploads for JPEG images and CSV files."""
    # 1. Valid JPEG
    jpeg_bytes = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00' + b'\x00' * 50
    resp = owner_client.post('/documents/upload', data={
        'title': 'Profile Photo',
        'file': (io.BytesIO(jpeg_bytes), 'photo.jpg')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    assert b"Profile Photo" in resp.data

    # 2. Valid CSV
    csv_bytes = b'id,name,role\n1,Alice,Owner\n2,Bob,Viewer\n'
    resp = owner_client.post('/documents/upload', data={
        'title': 'User Roster',
        'file': (io.BytesIO(csv_bytes), 'roster.csv')
    }, content_type='multipart/form-data', follow_redirects=True)
    assert resp.status_code == 200
    assert b"User Roster" in resp.data


def test_administrator_access_without_grants_is_denied(owner_client, admin_client):
    """
    Zero-Trust Policy Test:
    Administrators are NOT exempt from document access control.
    An administrator without ownership or an explicit per-document grant is denied.
    """
    # 1. Owner uploads confidential document
    doc_id = upload_sample_doc(owner_client, title="Executive Compensation Confidential")

    # 2. Administrator attempts to view document metadata -> 403 Forbidden
    resp = admin_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 403
    assert b"Access denied" in resp.data or b"Forbidden" in resp.data

    # 3. Administrator attempts to download document -> 403 Forbidden
    resp = admin_client.get(f'/documents/{doc_id}/download')
    assert resp.status_code == 403

    # 4. Administrator listing documents does NOT see this document
    list_resp = admin_client.get('/documents/')
    assert list_resp.status_code == 200
    assert b"Executive Compensation Confidential" not in list_resp.data

    # 5. Owner explicitly grants 'read' permission to the administrator
    grant_resp = owner_client.post(f'/documents/{doc_id}/permissions/grant', data={
        'email': 'admin@trustvault.local',
        'permission_level': 'read'
    }, follow_redirects=True)
    assert grant_resp.status_code == 200

    # 6. Now administrator CAN view metadata
    resp = admin_client.get(f'/documents/{doc_id}')
    assert resp.status_code == 200
    assert b"Executive Compensation Confidential" in resp.data

    # 7. Administrator CAN download
    download_resp = admin_client.get(f'/documents/{doc_id}/download')
    assert download_resp.status_code == 200
    assert download_resp.data == b"%PDF-1.4 sample pdf content"


