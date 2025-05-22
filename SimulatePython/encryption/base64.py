import base64

# 自定义字符表
CUSTOM_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STANDARD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def custom_b64encode(data: bytes) -> str:
    # 1. 标准Base64编码
    standard = base64.b64encode(data).decode()
    # 2. 替换字符表
    translation = str.maketrans(STANDARD_ALPHA, CUSTOM_ALPHA)
    return standard.translate(translation)