# Custom OAuth Provider

A minimal, from-scratch implementation of the **OAuth 2.0 Authorization
Code flow**, built with Flask and SQLite. It plays both roles:

- **Provider** — issues authorization codes and access tokens, exposes a
  protected resource endpoint.
- **Demo client** — a small script that walks through the entire flow
  against the provider, in-process, to prove it works end to end.

This is an educational/demo implementation, not a production-grade
OAuth server (no PKCE, no HTTPS enforcement, no refresh tokens,
plaintext demo passwords). It focuses on getting the core mechanics of
the Authorization Code grant right.

## How the Authorization Code flow works here

1. **Registration (pre-seeded).** The provider has a `clients` table
   of registered apps: `client_id`, `client_secret`, and the single
   `redirect_uri` they're allowed to use. A demo client
   (`demo-client-id` / `demo-client-secret`, redirect URI
   `http://localhost:9000/callback`) and a demo user (`alice` /
   `password123`) are seeded automatically when the app starts.

2. **`GET /authorize?client_id=...&redirect_uri=...&response_type=code&state=...`**
   The provider validates that `client_id` is registered and that
   `redirect_uri` exactly matches what was registered for it. If
   either check fails, it returns `400` — it never redirects to an
   unregistered URI. On success, it renders a simple consent/login
   page.

3. **`POST /authorize`** (form submission from the consent page). The
   user supplies credentials and either approves or denies. On
   approval with valid credentials, the provider mints a short-lived
   (60s), single-use authorization `code` bound to that
   `client_id` + `redirect_uri` + `username`, and redirects the
   browser to `redirect_uri?code=...&state=...`.

4. **`POST /token`** with `grant_type=authorization_code`, `code`,
   `redirect_uri`, `client_id`, `client_secret`. The provider checks,
   in order: the client exists and the secret matches; the code
   exists; the code hasn't already been used; the code hasn't
   expired; and the `client_id`/`redirect_uri` on the request match
   what the code was originally issued for. Any failure returns
   `400`/`401` with an `error` field and the code is never marked
   used on failure. On success, the code is marked used (so it can
   never be redeemed again) and a bearer `access_token` is returned
   (1 hour TTL).

5. **`GET /userinfo`** with header `Authorization: Bearer <access_token>`.
   Returns the token's associated `username` and `client_id` if the
   token exists and hasn't expired, otherwise `401`.

## Project layout

```
oauth_provider/
  __init__.py   # create_app() application factory
  db.py         # SQLite schema + connection helper
  models.py     # client/user/code/token data access
  views.py      # /authorize, /token, /userinfo routes
demo_client.py  # end-to-end demo walkthrough (no real HTTP)
tests/
  test_oauth.py # unit tests
```

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the demo client walkthrough

The demo client drives the entire flow using Flask's test client
(direct WSGI calls, no sockets) against an in-memory database, and
prints each step:

```bash
python demo_client.py
```

Expected output ends with:

```
Full Authorization Code flow completed successfully.
```

### Run the provider as a real local server

```bash
export FLASK_APP="oauth_provider:create_app"
flask run --port 8000
```

Then, from another terminal, walk through the flow with `curl`:

```bash
# 1. Fetch the consent page (would normally be opened in a browser)
curl "http://localhost:8000/authorize?client_id=demo-client-id&redirect_uri=http://localhost:9000/callback&response_type=code&state=xyz123"

# 2. Approve as the demo user (follow redirects disabled so we can see the Location header)
curl -i -X POST http://localhost:8000/authorize \
  -d "client_id=demo-client-id" \
  -d "redirect_uri=http://localhost:9000/callback" \
  -d "state=xyz123" \
  -d "username=alice" \
  -d "password=password123" \
  -d "decision=approve"
# -> HTTP/1.1 302 FOUND
# -> Location: http://localhost:9000/callback?code=<CODE>&state=xyz123

# 3. Exchange the code for an access token
curl -X POST http://localhost:8000/token \
  -d "grant_type=authorization_code" \
  -d "code=<CODE>" \
  -d "redirect_uri=http://localhost:9000/callback" \
  -d "client_id=demo-client-id" \
  -d "client_secret=demo-client-secret"
# -> {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}

# 4. Call the protected endpoint
curl http://localhost:8000/userinfo -H "Authorization: Bearer <ACCESS_TOKEN>"
# -> {"username": "alice", "client_id": "demo-client-id"}
```

## Running the tests

```bash
pytest -v
```

Each test spins up a fresh `create_app(testing=True)` instance backed
by an in-memory SQLite database, so tests are fully isolated from each
other and from any real file on disk. Covered scenarios:

- `/authorize` shows the consent page for a valid registered client
- `/authorize` rejects an unknown `client_id`
- `/authorize` rejects a mismatched `redirect_uri`
- an authorization code is only issued for a valid client + redirect
  after approval
- `/token` succeeds with a valid, unused, unexpired code
- a code cannot be redeemed twice
- an expired code is rejected
- a mismatched `redirect_uri` at the token endpoint is rejected
- an invalid `client_secret` is rejected
- `/userinfo` returns the user for a valid access token
- `/userinfo` rejects missing/garbage tokens
- `/userinfo` rejects an expired token

## CI

`.github/workflows/tests.yml` runs the full test suite on every push
and pull request against Python 3.11 and 3.12.

## License

MIT — see [LICENSE](LICENSE).
