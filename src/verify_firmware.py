from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from hash_utils import sha256_of_file
import sys

def verify_firmware(firmware_path: str, signature_path: str, public_key_path: str) -> bool:
    print(f"[INFO] Reading firmware: {firmware_path}")
    firmware_data = Path(firmware_path).read_bytes()

    print(f"[INFO] Reading signature: {signature_path}")
    signature = Path(signature_path).read_bytes()

    print(f"[INFO] Loading public key: {public_key_path}")
    public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())

    print("[INFO] Calculating SHA-256...")
    firmware_hash = sha256_of_file(firmware_path)
    print(f"[INFO] Firmware SHA-256: {firmware_hash}")

    print("[INFO] Verifying signature...")
    try:
        public_key.verify(
            signature,
            firmware_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[OK] Verification passed")
        return True
    except InvalidSignature:
        print("[FAIL] Verification failed")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python src/verify_firmware.py <firmware> <signature> <public_key>")
        raise SystemExit(1)

    ok = verify_firmware(sys.argv[1], sys.argv[2], sys.argv[3])
    raise SystemExit(0 if ok else 1)