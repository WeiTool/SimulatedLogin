import base64

CUSTOM_BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


class CustomB64Encoder:
    def __init__(self):
        self._std_to_custom = str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            CUSTOM_BASE64_ALPHABET
        )

    def encode(self, data: bytes) -> str:
        std_b64 = base64.b64encode(data).decode('ascii')
        return std_b64.translate(self._std_to_custom).rstrip("=")
