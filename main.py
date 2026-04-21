from flask import Flask, request, jsonify, render_template
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import ssl
import like_pb2
import like_count_pb2
import uid_generator_pb2
import MajoRLoGinrEq_pb2
import MajoRLoGinrEs_pb2
from google.protobuf.message import DecodeError
import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import time
from datetime import datetime, timedelta

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# ==================== TOKEN AUTO-REFRESH ====================
ACCOUNTS_FILE = "accounts.txt"
TOKEN_FILE_BD = "token_bd.json"
TOKEN_REFRESH_INTERVAL_HOURS = 2
TOKEN_API_URL = "https://rizerxguestaccountacceee.vercel.app/rizer"

def load_accounts_from_file():
    accounts = []
    try:
        if not os.path.exists(ACCOUNTS_FILE):
            app.logger.error(f"Accounts file {ACCOUNTS_FILE} not found.")
            return accounts
        with open(ACCOUNTS_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    app.logger.warning(f"Line {line_num}: invalid format. Skipping.")
                    continue
                uid, password = line.split(":", 1)
                accounts.append({"uid": uid.strip(), "password": password.strip()})
        app.logger.info(f"Loaded {len(accounts)} accounts from {ACCOUNTS_FILE}.")
    except Exception as e:
        app.logger.error(f"Error loading accounts file: {e}")
    return accounts

def _enc_aes_raw(data_bytes):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data_bytes, 16))

def fetch_token_from_api(uid, password):
    """Generate JWT directly via Garena guest OAuth + Free Fire MajorLogin."""
    try:
        # Step 1: Garena guest OAuth -> open_id + access_token
        oauth = requests.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            data={
                "uid": uid, "password": password, "response_type": "token",
                "client_id": "100067", "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            }, timeout=15
        )
        if oauth.status_code != 200:
            app.logger.error(f"Garena OAuth HTTP {oauth.status_code} for UID {uid}")
            return None
        oj = oauth.json()
        oid, gat = oj.get("open_id"), oj.get("access_token")
        if not oid or not gat:
            app.logger.error(f"Garena returned no open_id/token for UID {uid}: {oj}")
            return None

        # Step 2: MajorLogin -> JWT
        ml = MajoRLoGinrEq_pb2.MajorLogin()
        ml.event_time = str(datetime.now())[:-7]
        ml.game_name = "free fire"
        ml.platform_id = 1
        ml.client_version = "1.120.1"
        ml.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        ml.system_hardware = "Handheld"
        ml.telecom_operator = "Verizon"
        ml.network_type = "WIFI"
        ml.screen_width = 1920
        ml.screen_height = 1080
        ml.screen_dpi = "280"
        ml.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        ml.memory = 3003
        ml.gpu_renderer = "Adreno (TM) 640"
        ml.gpu_version = "OpenGL ES 3.1 v1.46"
        ml.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        ml.client_ip = "223.191.51.89"
        ml.language = "en"
        ml.open_id = str(oid)
        ml.open_id_type = "4"
        ml.device_type = "Handheld"
        ml.memory_available.version = 55
        ml.memory_available.hidden_value = 81
        ml.access_token = str(gat)
        ml.platform_sdk_id = 1
        ml.network_operator_a = "Verizon"
        ml.network_type_a = "WIFI"
        ml.client_using_version = "7428b253defc164018c604a1ebbfebdf"
        ml.external_storage_total = 36235
        ml.external_storage_available = 31335
        ml.internal_storage_total = 2519
        ml.internal_storage_available = 703
        ml.game_disk_storage_available = 25010
        ml.game_disk_storage_total = 26628
        ml.external_sdcard_avail_storage = 32992
        ml.external_sdcard_total_storage = 36235
        ml.login_by = 3
        ml.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
        ml.reg_avatar = 1
        ml.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
        ml.channel_type = 3
        ml.cpu_type = 2
        ml.cpu_architecture = "64"
        ml.client_version_code = "2019118695"
        ml.graphics_api = "OpenGLES2"
        ml.supported_astc_bitset = 16383
        ml.login_open_id_type = 4
        ml.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
        ml.loading_time = 13564
        ml.release_channel = "android"
        ml.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
        ml.android_engine_init_flag = 110009
        ml.if_push = 1
        ml.is_vpn = 1
        ml.origin_platform_type = "4"
        ml.primary_platform_type = "4"

        payload = _enc_aes_raw(ml.SerializeToString())
        headers = {
            "Host": "loginbp.ggblueshark.com",
            "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*",
            "Authorization": "Bearer",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2022.3.47f1",
        }
        r = requests.post("https://loginbp.ggblueshark.com/MajorLogin", data=payload,
                          headers=headers, verify=False, timeout=15)
        if r.status_code != 200:
            app.logger.error(f"MajorLogin HTTP {r.status_code} for UID {uid}")
            return None
        ml_res = MajoRLoGinrEs_pb2.MajorLoginRes()
        ml_res.ParseFromString(r.content)
        if not ml_res.token:
            app.logger.error(f"Empty JWT for UID {uid}")
            return None
        return {"uid": str(ml_res.account_uid), "token": ml_res.token, "region": "BD"}
    except Exception as e:
        app.logger.error(f"Local token fetch error (UID {uid}): {e}")
        return None

def update_token_json(new_accounts_data):
    try:
        existing = []
        if os.path.exists(TOKEN_FILE_BD):
            try:
                with open(TOKEN_FILE_BD, "r") as f:
                    existing = json.load(f)
                    if not isinstance(existing, list):
                        existing = []
            except json.JSONDecodeError:
                existing = []
        merged = {item["uid"]: item for item in existing}
        for item in new_accounts_data:
            merged[item["uid"]] = item
        with open(TOKEN_FILE_BD, "w") as f:
            json.dump(list(merged.values()), f, indent=2)
        app.logger.info(f"{TOKEN_FILE_BD} updated with {len(merged)} entries.")
        return True
    except Exception as e:
        app.logger.error(f"Failed to write token file: {e}")
        return False

def refresh_all_tokens():
    app.logger.info("Starting token refresh...")
    accounts = load_accounts_from_file()
    if not accounts:
        return
    successes = []
    for idx, acc in enumerate(accounts, 1):
        app.logger.info(f"[{idx}/{len(accounts)}] UID {acc['uid']}")
        result = fetch_token_from_api(acc['uid'], acc['password'])
        if result:
            successes.append(result)
        time.sleep(0.3)
    if successes:
        update_token_json(successes)
    app.logger.info(f"Refresh complete. Success: {len(successes)}/{len(accounts)}")

def scheduled_token_refresh():
    while True:
        try:
            refresh_all_tokens()
        except Exception as e:
            app.logger.error(f"Scheduler error: {e}")
        time.sleep(TOKEN_REFRESH_INTERVAL_HOURS * 3600)

def start_background_scheduler():
    t = threading.Thread(target=scheduled_token_refresh, daemon=True)
    t.start()
    app.logger.info("Token refresh scheduler started.")

# ==================== CORE LIKE ENGINE ====================
def load_tokens(server_name):
    try:
        if server_name == "IND":
            path = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            path = "token_br.json"
        else:
            path = "token_bd.json"
        if not os.path.exists(path):
            app.logger.error(f"Token file missing: {path}")
            return None
        with open(path, "r") as f:
            tokens = json.load(f)
        return tokens or None
    except Exception as e:
        app.logger.error(f"Token load failed ({server_name}): {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption failed: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Like protobuf failed: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"send_request exception: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if protobuf_message is None: return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None: return None
        tokens = load_tokens(server_name)
        if not tokens: return None
        tasks = [send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url) for i in range(100)]
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"send_multiple_requests exception: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"UID protobuf failed: {e}")
        return None

def enc(uid):
    pb = create_protobuf(uid)
    return encrypt_message(pb) if pb else None

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB53"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        return decode_protobuf(response.content)
    except Exception as e:
        app.logger.error(f"make_request exception: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"DecodeError: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Decode failed: {e}")
        return None

# ==================== ROUTES ====================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = (request.args.get("server_name") or request.args.get("region") or "BD").upper()
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    try:
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": f"No tokens loaded for {server_name}. Tokens auto-refresh in the background; try again shortly."}), 503

        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "UID encryption failed"}), 500

        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            return jsonify({"error": "Failed to retrieve initial player info"}), 500

        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0) or 0)
        app.logger.info(f"Initial likes: {before_like}")

        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Failed to retrieve player info after likes"}), 500

        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0) or 0)
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0) or 0)
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        like_given = after_like - before_like

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": 1 if like_given > 0 else 2
        })
    except Exception as e:
        app.logger.error(f"Main request failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/refresh-tokens', methods=['POST'])
def manual_refresh():
    threading.Thread(target=refresh_all_tokens, daemon=True).start()
    return jsonify({"status": "refresh started"})

@app.route('/health')
def health():
    tokens_bd = load_tokens("BD")
    return jsonify({
        "status": "ok",
        "version": "OB53",
        "tokens_bd": len(tokens_bd) if tokens_bd else 0
    })

if __name__ == '__main__':
    start_background_scheduler()
    app.run(host='0.0.0.0', port=5000, threaded=True)
