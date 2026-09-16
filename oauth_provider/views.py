"""HTTP endpoints implementing the OAuth 2.0 Authorization Code flow."""
import time
from urllib.parse import urlencode

from flask import Blueprint, jsonify, redirect, render_template_string, request

from . import models

bp = Blueprint("oauth", __name__)


CONSENT_PAGE = """
<!doctype html>
<title>Authorize</title>
<h1>{{ client_name }} would like to access your account</h1>
<p>This app is requesting permission to view your basic profile info.</p>
<form method="post">
  <input type="hidden" name="client_id" value="{{ client_id }}">
  <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
  <input type="hidden" name="state" value="{{ state }}">
  <label>Username <input name="username"></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>
"""


@bp.route("/authorize", methods=["GET", "POST"])
def authorize():
    """Consent/login screen (GET) and approval handler (POST).

    On approval, issues a short-lived authorization code bound to the
    requesting client_id and redirect_uri, then redirects back to the
    client with `code` and `state` query parameters.
    """
    client_id = request.values.get("client_id")
    redirect_uri = request.values.get("redirect_uri")
    state = request.values.get("state", "")
    response_type = request.values.get("response_type", "code")

    client = models.get_client(client_id) if client_id else None
    if client is None or client["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_client_or_redirect_uri"), 400

    if response_type != "code":
        return jsonify(error="unsupported_response_type"), 400

    if request.method == "GET":
        return render_template_string(
            CONSENT_PAGE,
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
        )

    # POST: the consent form was submitted.
    decision = request.form.get("decision")
    username = request.form.get("username")
    password = request.form.get("password")

    if decision != "approve":
        return jsonify(error="access_denied"), 403

    if not models.verify_user(username, password):
        return jsonify(error="invalid_credentials"), 401

    code = models.create_auth_code(client_id, redirect_uri, username)
    query = urlencode({"code": code, "state": state})
    return redirect(f"{redirect_uri}?{query}")


@bp.route("/token", methods=["POST"])
def token():
    """Exchange a valid authorization code + client credentials for an
    access token. Rejects reused/expired codes and mismatched
    redirect_uri/client.
    """
    grant_type = request.values.get("grant_type")
    code = request.values.get("code")
    redirect_uri = request.values.get("redirect_uri")
    client_id = request.values.get("client_id")
    client_secret = request.values.get("client_secret")

    if grant_type != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    client = models.get_client(client_id)
    if client is None or client["client_secret"] != client_secret:
        return jsonify(error="invalid_client"), 401

    auth_code = models.get_auth_code(code)
    if auth_code is None:
        return jsonify(error="invalid_grant", detail="unknown code"), 400

    if auth_code["used"]:
        return jsonify(error="invalid_grant", detail="code already used"), 400

    if auth_code["expires_at"] < time.time():
        return jsonify(error="invalid_grant", detail="code expired"), 400

    if auth_code["client_id"] != client_id or auth_code["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_grant", detail="client/redirect mismatch"), 400

    models.mark_code_used(code)
    access_token, expires_at = models.create_access_token(client_id, auth_code["username"])

    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=int(expires_at - time.time()),
    )


@bp.route("/userinfo", methods=["GET"])
def userinfo():
    """Protected endpoint requiring a valid Bearer access token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify(error="invalid_token"), 401

    access_token = auth_header[len("Bearer "):]
    token_row = models.get_token(access_token)

    if token_row is None or token_row["expires_at"] < time.time():
        return jsonify(error="invalid_token"), 401

    return jsonify(username=token_row["username"], client_id=token_row["client_id"])
