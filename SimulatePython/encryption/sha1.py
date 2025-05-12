import hashlib


def get_chksum(
        username: str,
        hmd5: str,
        acid: int,
        client_ip: str,
        n: int,
        utype: int,
        param_i: str,
        token: str,
) -> str:
    acid_str = str(acid)
    n_str = str(n)
    utype_str = str(utype)

    parts = ["", username, hmd5, acid_str, client_ip, n_str, utype_str, param_i]

    joined_str = token.join(parts)

    sha1 = hashlib.sha1()
    sha1.update(joined_str.encode("utf-8"))
    return sha1.hexdigest()
