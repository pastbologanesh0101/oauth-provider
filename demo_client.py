"""Demo OAuth client walkthrough.

Runs entirely in-process against the provider app using Flask's test
client (no real HTTP sockets are opened), demonstrating the full
Authorization Code flow end to end:

    1. GET  /authorize   -> consent/login page is shown
    2. POST /authorize   -> user approves, provider issues a code and
                             redirects back to the client's redirect_uri
    3. POST /token       -> client exchanges the code + its credentials
                             for an access token
    4. GET  /userinfo    -> client calls the protected endpoint with the
                             access token

Run with:

    python demo_client.py
"""
from urllib.parse import parse_qs, urlparse

from oauth_provider import create_app

CLIENT_ID = "demo-client-id"
CLIENT_SECRET = "demo-client-secret"
REDIRECT_URI = "http://localhost:9000/callback"
USERNAME = "alice"
PASSWORD = "password123"


def run_demo():
    app = create_app(testing=True)
    client = app.test_client()

    print("1. GET /authorize (show consent page)")
    resp = client.get(
        "/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "state": "xyz123",
        },
    )
    assert resp.status_code == 200
    print("   consent page rendered OK")

    print("2. POST /authorize (user logs in and approves)")
    resp = client.post(
        "/authorize",
        data={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "state": "xyz123",
            "username": USERNAME,
            "password": PASSWORD,
            "decision": "approve",
        },
    )
    assert resp.status_code == 302
    location = resp.headers["Location"]
    query = parse_qs(urlparse(location).query)
    code = query["code"][0]
    print(f"   redirected with authorization code: {code[:12]}...")

    print("3. POST /token (exchange code for access token)")
    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert resp.status_code == 200
    token_data = resp.get_json()
    access_token = token_data["access_token"]
    print(
        f"   access token issued: {access_token[:12]}... "
        f"(expires_in={token_data['expires_in']}s)"
    )

    print("4. GET /userinfo (call protected endpoint with access token)")
    resp = client.get(
        "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert resp.status_code == 200
    print(f"   userinfo: {resp.get_json()}")

    print("\nFull Authorization Code flow completed successfully.")


if __name__ == "__main__":
    run_demo()
