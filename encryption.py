import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

SALT_PATH = "data/salt.bin"

def _get_salt() -> bytes:
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(SALT_PATH):
        with open(SALT_PATH, "wb") as f:
            f.write(os.urandom(16))
    with open(SALT_PATH, "rb") as f:
        return f.read()

def derive_key(master_password: str) -> bytes:
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

def get_fernet(master_password: str) -> Fernet:
    key = derive_key(master_password)
    return Fernet(key)