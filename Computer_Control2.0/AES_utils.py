from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

AES_KEY = b'Sixteen byte key'  # Must be 16, 24, or 32 bytes
IV_SIZE = 16  # AES block size


def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode()


def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:IV_SIZE]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[IV_SIZE:]), AES.block_size)
    return decrypted_bytes.decode()
