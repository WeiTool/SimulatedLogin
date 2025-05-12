import hmac
import hashlib


def get_hmd5(password: str, token: str) -> str:
    key_bytes = token.encode("utf-8")
    msg_bytes = password.encode("utf-8")
    hmac_md5 = hmac.new(key_bytes, msg_bytes, hashlib.md5)
    return hmac_md5.hexdigest()
