import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


SALT_FILE = "encryption.salt"

# Stores the encryption cipher only while the program is running
_cipher = None


# --------------------------------
# CREATE / LOAD SALT
# --------------------------------

def get_salt():

    if not os.path.exists(SALT_FILE):

        salt = os.urandom(16)

        with open(SALT_FILE, "wb") as file:
            file.write(salt)

        return salt

    with open(SALT_FILE, "rb") as file:
        return file.read()


# --------------------------------
# DERIVE ENCRYPTION KEY
# --------------------------------

def initialize_encryption(master_password):

    global _cipher

    salt = get_salt()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(master_password.encode("utf-8"))
    )

    _cipher = Fernet(key)


# --------------------------------
# ENCRYPT PASSWORD
# --------------------------------

def encrypt_password(password):

    if _cipher is None:
        raise RuntimeError(
            "Encryption is not initialized. Please login first."
        )

    encrypted = _cipher.encrypt(
        password.encode("utf-8")
    )

    return encrypted.decode("utf-8")


# --------------------------------
# DECRYPT PASSWORD
# --------------------------------

def decrypt_password(encrypted_password):

    if _cipher is None:
        raise RuntimeError(
            "Encryption is not initialized. Please login first."
        )

    decrypted = _cipher.decrypt(
        encrypted_password.encode("utf-8")
    )

    return decrypted.decode("utf-8")