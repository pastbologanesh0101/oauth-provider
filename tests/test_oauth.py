"""Unit tests for the Custom OAuth Provider's Authorization Code flow."""
from urllib.parse import parse_qs, urlparse

import pytest

from oauth_provider import create_app, models

CLIENT_ID = "demo-client-id"
CLIENT_SECRET = "demo-client-secret"
REDIRECT_URI = "http://localhost:9000/callback"
USERNAME = "alice"
PASSWORD = "password123"


@pytest.fixture
def app():
    return create_app(testing=True)


@pytest.fixture
def client(app):
    return app.test_client()


def approve_and_get_code(client, redirect_uri=REDIRECT_URI, state="s1"):
    """Helper: drive /authorize through to an issued code."""
    resp = client.post(
        "/authorize",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "state": state,
            "username": USERNAME,
            "password": PASSWORD,
            "decision": "approve",
        },
    )
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["Location"]).query)
    return query["code"][0]


def exchange_code(
    client,
    code,
    redirect_uri=REDIRECT_URI,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
):
    """Helper: POST /token for a given code + credentials."""
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )


def test_authorize_shows_consent_for_valid_client(client):
    resp = client.get(
        "/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
        },
    )
    assert resp.status_code == 200
    assert b"Approve" in resp.data


def test_authorize_rejects_unknown_client(client):
    resp = client.get(
        "/authorize",
        query_string={
            "client_id": "no-such-client",
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
        },
    )
    assert resp.status_code == 400


def test_authorize_rejects_mismatched_redirect_uri(client):
    resp = client.get(
        "/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": "http://evil.example/cb",
            "response_type": "code",
        },
    )
    assert resp.status_code == 400


def test_authorize_issues_code_only_for_valid_client_and_redirect(client):
    code = approve_and_get_code(client)
    assert code
    with client.application.app_context():
        row = models.get_auth_code(code)
    assert row is not None
    assert row["client_id"] == CLIENT_ID
    assert row["redirect_uri"] == REDIRECT_URI
    assert row["used"] == 0


def test_token_exchange_succeeds_with_valid_code(client):
    code = approve_and_get_code(client)
    resp = exchange_code(client, code)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["token_type"] == "Bearer"
    assert "access_token" in data
    assert data["expires_in"] > 0


def test_code_cannot_be_reused(client):
    code = approve_and_get_code(client)
    first = exchange_code(client, code)
    assert first.status_code == 200

    second = exchange_code(client, code)
    assert second.status_code == 400
    assert second.get_json()["error"] == "invalid_grant"


def test_expired_code_rejected(client):
    with client.application.app_context():
        expired_code = models.create_auth_code(
            CLIENT_ID, REDIRECT_URI, USERNAME, ttl_seconds=-10
        )
    resp = exchange_code(client, expired_code)
    assert resp.status_code == 400
    assert "expired" in resp.get_json().get("detail", "")


def test_mismatched_redirect_uri_rejected_at_token(client):
    code = approve_and_get_code(client)
    resp = exchange_code(client, code, redirect_uri="http://other.example/cb")
    assert resp.status_code == 400


def test_invalid_client_secret_rejected(client):
    code = approve_and_get_code(client)
    resp = exchange_code(client, code, client_secret="wrong-secret")
    assert resp.status_code == 401


def test_userinfo_requires_valid_token(client):
    code = approve_and_get_code(client)
    token_resp = exchange_code(client, code)
    access_token = token_resp.get_json()["access_token"]

    resp = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == USERNAME


def test_userinfo_rejects_missing_or_garbage_token(client):
    resp = client.get("/userinfo")
    assert resp.status_code == 401

    resp = client.get("/userinfo", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_userinfo_rejects_expired_token(client):
    with client.application.app_context():
        expired_token, _ = models.create_access_token(
            CLIENT_ID, USERNAME, ttl_seconds=-10
        )
    resp = client.get(
        "/userinfo", headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert resp.status_code == 401
