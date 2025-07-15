from Crypto.Cipher import AES
import base64, os

BLOCK_SIZE = 16
KEY = os.environ["AES_KEY"].encode()[:32]

def pad(data: str) -> str:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + chr(pad_len) * pad_len

def unpad(data: str) -> str:
    return data[:-ord(data[-1])]

def encrypt(raw: str) -> str:
    raw_p = pad(raw)
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw_p.encode())).decode()

def decrypt(enc: str) -> str:
    data = base64.b64decode(enc)
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[BLOCK_SIZE:]).decode())
