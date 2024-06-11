import base64
import hmac
import hashlib
import struct
import time


def generate_key(secret_key):
    key = base64.b32decode(secret_key)
    return key


def generate_otp(key):
    timestamp = time.time()
    timestamp = int(timestamp) // 30
    print(timestamp)
    timestamp = struct.pack(">Q", timestamp)
    hmac_hash = hmac.new(key, timestamp, hashlib.sha1).digest()
    print(hmac_hash.hex())
    offset = hmac_hash[-1] & 0x0F
    otp = (struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return otp

secret_key = "Github 2FA认证提供的经过base32（RFC3548）编码后的secretKey"  # 密钥
key = generate_key(secret_key)
otp = generate_otp(key)  # 生成TOTP密码
print("TOTP密码：", otp)
