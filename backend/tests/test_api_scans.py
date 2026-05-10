import pytest

from app.models.scan import Scan, ScanStatus


# ── POST /scans ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_scan_returns_201(client):
    response = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "queued"
    assert data["target_url"] == "https://example.com/"
    assert "id" in data
    assert data["total_findings"] == 0
    assert data["total_urls_found"] == 0


@pytest.mark.asyncio
async def test_create_scan_applies_default_config(client):
    response = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    assert response.status_code == 201
    config = response.json()["config"]
    assert "modules" in config
    assert "crawl_depth" in config


@pytest.mark.asyncio
async def test_create_scan_accepts_custom_config(client):
    response = await client.post(
        "/api/v1/scans",
        json={
            "target_url": "https://example.com",
            "authorisation_confirmed": True,
            "config": {"modules": ["sqli"], "crawl_depth": 1},
        },
    )
    assert response.status_code == 201
    assert response.json()["config"]["modules"] == ["sqli"]


@pytest.mark.asyncio
async def test_create_scan_rejects_missing_authorisation(client):
    response = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": False},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_scan_rejects_invalid_url(client):
    response = await client.post(
        "/api/v1/scans",
        json={"target_url": "not-a-url", "authorisation_confirmed": True},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_scan_rejects_non_http_scheme(client):
    response = await client.post(
        "/api/v1/scans",
        json={"target_url": "ftp://example.com", "authorisation_confirmed": True},
    )
    assert response.status_code == 422


# ── GET /scans ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_scans_empty(client):
    response = await client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_list_scans_returns_created_scans(client):
    for _ in range(3):
        await client.post(
            "/api/v1/scans",
            json={"target_url": "https://example.com", "authorisation_confirmed": True},
        )
    response = await client.get("/api/v1/scans")
    assert response.status_code == 200
    assert response.json()["total"] == 3


@pytest.mark.asyncio
async def test_list_scans_filter_by_status(client):
    await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    response = await client.get("/api/v1/scans?status=queued")
    assert response.status_code == 200
    assert response.json()["total"] == 1

    response = await client.get("/api/v1/scans?status=completed")
    assert response.json()["total"] == 0


# ── GET /scans/{id} ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_scan_returns_correct_data(client):
    create = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    scan_id = create.json()["id"]
    response = await client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    assert response.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_get_scan_404_for_unknown_id(client):
    response = await client.get("/api/v1/scans/nonexistent-id")
    assert response.status_code == 404


# ── POST /scans/{id}/cancel ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancel_queued_scan(client):
    create = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    scan_id = create.json()["id"]
    response = await client.post(f"/api/v1/scans/{scan_id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_already_cancelled_returns_409(client, db_session):
    scan = Scan(target_url="https://example.com", status=ScanStatus.cancelled)
    db_session.add(scan)
    await db_session.commit()

    response = await client.post(f"/api/v1/scans/{scan.id}/cancel")
    assert response.status_code == 409


# ── DELETE /scans/{id} ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_scan_returns_204(client):
    create = await client.post(
        "/api/v1/scans",
        json={"target_url": "https://example.com", "authorisation_confirmed": True},
    )
    scan_id = create.json()["id"]
    response = await client.delete(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 204

    response = await client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 404
