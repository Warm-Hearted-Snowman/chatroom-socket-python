import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode


def encrypt(password, salt, key):
    # Derive a key from the password using PBKDF2
    derived_key = PBKDF2(password, salt, dkLen=16)

    # Use the derived key to encrypt the key
    cipher = AES.new(derived_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(key, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    cipher_text = b64encode(ct_bytes).decode('utf-8')
    result = {'iv': iv, 'ciphertext': cipher_text, 'salt': b64encode(salt).decode('utf-8')}
    return result


def generate_random_key(length):
    return secrets.token_bytes(length)


def decrypt(password, key):
    try:
        iv = b64decode(key['iv'])
        cipher_text = b64decode(key['ciphertext'])
        salt = b64decode(key['salt'])

        # Derive the key from the password using PBKDF2
        derived_key = PBKDF2(password, salt, dkLen=16)

        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
        return plain_text
    except (ValueError, KeyError):
        return None
