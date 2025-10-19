# mfa.py
import base64
import io
import qrcode
import pyotp

ISSUER_NAME = "CS-Lab3"

def random_secret():
    """Generate a 160-bit base32 secret suitable for TOTP/HOTP."""
    return pyotp.random_base32()

def otpauth_uri_totp(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=ISSUER_NAME)

def otpauth_uri_hotp(secret: str, username: str, counter: int = 0) -> str:
    return f"otpauth://hotp/{ISSUER_NAME}:{username}?secret={secret}&issuer={ISSUER_NAME}&counter={counter}"

def qr_data_url(uri: str) -> str:
    """Return a data: URL PNG QR image for the given otpauth URI."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"

# ---- Verification helpers ----
def verify_totp(secret: str, code: str, window: int = 0) -> bool:
    """
    window=0 → only current 30s step.
    window=1 → accept ±1 time step (about ±30s).
    """
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(code, valid_window=window))

def verify_hotp_and_advance(secret: str, code: str, counter: int, look_ahead: int = 0):
    """
    HOTP verification with optional look-ahead (desync recovery).
    look_ahead=0 → only current counter.
    look_ahead=1 → accept counter or counter+1.

    Returns (ok: bool, new_counter: int|None, matched_offset: int|None).
    On success, new_counter is set to the *next* counter value (matched+1).
    """
    hotp = pyotp.HOTP(secret)
    for offset in range(0, max(0, look_ahead) + 1):
        if hotp.verify(code, counter + offset):
            return True, (counter + offset + 1), offset
    return False, None, None
