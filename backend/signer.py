from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from backend.crypto_utils import sha256_bytes

def sign_firmware_bytes(firmware_bytes: bytes, private_key):
    firmware_hash = sha256_bytes(firmware_bytes)
    signature = private_key.sign(
        firmware_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return firmware_hash, signature