import requests
import time
import json
import socket
from typing import Dict, Tuple
from encryption.base64 import CustomB64Encoder
from encryption.encode import x_encode
from encryption.md5 import get_hmd5
from encryption.sha1 import get_chksum

# ---------------------------- 全局配置 ----------------------------
header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0'
}
get_challenge_api = "http://172.16.130.31/cgi-bin/get_challenge"
srun_portal_api = "http://172.16.130.31/cgi-bin/srun_portal"
n = 200
ac_id = 7
enc_ver = "srun_bx1"
utype = 1


# ---------------------------- IP 检测逻辑 ----------------------------
def detect_ip(username: str) -> str:
    try:
        params = {
            "callback": "sdu",
            "username": username,
            "ip": "",
            "_": int(time.time() - 2)
        }
        response = requests.get(get_challenge_api, params=params, headers=header, timeout=5)
        response.raise_for_status()
        raw_text = response.text
        if not raw_text.startswith("sdu(") or not raw_text.endswith(")"):
            raise ValueError("Invalid JSONP response")
        data = json.loads(raw_text[4:-1])
        if "online_ip" not in data or not data["online_ip"]:
            raise ValueError("服务器未返回 online_ip 字段")
        return data["online_ip"]
    except Exception as e:
        print(f"[WARN] 自动检测 IP 失败: {str(e)}，尝试本地获取 IP")
        return get_local_ip()


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "0.0.0.0"


# ---------------------------- 核心逻辑 ----------------------------
def get_challenge(username: str, client_ip: str) -> Tuple[str, str]:
    try:
        params = {
            "callback": "sdu",
            "username": username,
            "ip": client_ip,
            "_": int(time.time() - 2)
        }
        response = requests.get(get_challenge_api, params=params, headers=header, timeout=5)
        response.raise_for_status()
        raw_text = response.text
        if not raw_text.startswith("sdu(") or not raw_text.endswith(")"):
            raise ValueError("Invalid JSONP response")
        data = json.loads(raw_text[4:-1])

        online_ip = data.get("online_ip", client_ip)
        return data["challenge"], online_ip
    except Exception as e:
        raise RuntimeError(f"获取 token 失败: {str(e)}")


def get_info(username: str, password: str, ip: str, token: str) -> str:
    info_json = json.dumps({
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc_ver
    }, separators=(',', ':'))

    xen_bytes = x_encode(info_json, token)

    encoder = CustomB64Encoder()
    return "{SRBX1}" + encoder.encode(xen_bytes)


# ---------------------------- 主流程 ----------------------------
def login(username: str, password: str, client_ip: str = "", auto_detect: bool = True) -> Dict:
    try:
        if auto_detect and not client_ip:
            client_ip = detect_ip(username)
            print(f"自动检测到 IP: {client_ip}")

        token, updated_ip = get_challenge(username, client_ip)
        if updated_ip != client_ip:
            print(f"服务器返回更新 IP: {updated_ip}")
            client_ip = updated_ip

        hmd5 = get_hmd5(password, token)

        info = get_info(username, password, client_ip, token)

        chksum = get_chksum(username, hmd5, ac_id, client_ip, n, utype, info, token)

        params = {
            "callback": "sdu",
            "action": "login",
            "username": username,
            "password": f"{{MD5}}{hmd5}",
            "ac_id": str(ac_id),
            "ip": client_ip,
            "info": info,
            "chksum": chksum,
            "n": str(n),
            "type": str(utype),
            "_": str(int(time.time()))
        }

        response = requests.get(srun_portal_api, params=params, headers=header)

        return json.loads(response.text[4:-1])
    except Exception as e:

        return {"error": str(e), "ecode": -1}

# ---------------------------- 新增注销功能 ----------------------------
def logout(username: str, client_ip: str = "", auto_detect: bool = True) -> Dict:
    try:
        if auto_detect and not client_ip:
            client_ip = detect_ip(username)
            print(f"自动检测到 IP: {client_ip}")

        params = {
            "callback": "sdu",
            "action": "logout",
            "username": username,
            "ip": client_ip,
            "ac_id": str(ac_id),
            "_": str(int(time.time()))
        }

        response = requests.get(srun_portal_api, params=params, headers=header)
        return json.loads(response.text[4:-1])
    except Exception as e:
        return {"error": str(e), "ecode": -1}

# ---------------------------- IP 检测逻辑 ----------------------------
def detect_ip(username: str) -> str:
    try:
        params = {
            "callback": "sdu",
            "username": username,
            "ip": "",
            "_": int(time.time() - 2)
        }
        response = requests.get(get_challenge_api, params=params, headers=header, timeout=5)
        response.raise_for_status()
        raw_text = response.text
        if not raw_text.startswith("sdu(") or not raw_text.endswith(")"):
            raise ValueError("Invalid JSONP response")
        data = json.loads(raw_text[4:-1])
        if "online_ip" not in data or not data["online_ip"]:
            raise ValueError("服务器未返回 online_ip 字段")
        return data["online_ip"]
    except Exception as e:
        print(f"[WARN] 自动检测 IP 失败: {str(e)}，尝试本地获取 IP")
        return get_local_ip()

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "0.0.0.0"

# ---------------------------- 主流程 ----------------------------
if __name__ == "__main__":
    # 用户交互菜单
    print("请选择操作：")
    print("1. 登录")
    print("2. 退出")
    choice = input("请输入数字 (1/2): ")

    username = "yourUsername@ctc"  # 修改为自己的用户名 @ctc是宿舍区域 @ynufe是教学区域
    password = "yourPassword"      # 修改为实际密码

    try:
        if choice == "1":
            result = login(username, password, auto_detect=True)
        elif choice == "2":
            result = logout(username, auto_detect=True)
        else:
            print("错误：无效选项，请输入 1 或 2")
            exit(1)

        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"操作失败: {str(e)}")