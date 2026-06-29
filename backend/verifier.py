from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from backend.crypto_utils import sha256_bytes

def verify_firmware_bytes(firmware_bytes: bytes, signature_bytes: bytes, public_key):
    firmware_hash = sha256_bytes(firmware_bytes)
    try:
        public_key.verify(
            signature_bytes,
            firmware_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True, firmware_hash, "Verification passed"
    except InvalidSignature:
        return False, firmware_hash, "Verification failed"