from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from hash_utils import sha256_of_file
import sys

PASSPHRASE = b"change-this-passphrase"

def sign_firmware(firmware_path: str, private_key_path: str, passphrase: bytes, signature_out_path: str):
    print(f"[INFO] Reading firmware: {firmware_path}")
    firmware_data = Path(firmware_path).read_bytes()

    print(f"[INFO] Calculating SHA-256...")
    firmware_hash = sha256_of_file(firmware_path)
    print(f"[INFO] Firmware SHA-256: {firmware_hash}")

    print(f"[INFO] Loading private key: {private_key_path}")
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=passphrase
    )

    print("[INFO] Signing firmware with RSA-PSS...")
    signature = private_key.sign(
        firmware_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    Path(signature_out_path).write_bytes(signature)
    print(f"[OK] Signature written to: {signature_out_path}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python src/sign_firmware.py <firmware> <private_key> <signature_out>")
        raise SystemExit(1)

    sign_firmware(sys.argv[1], sys.argv[2], PASSPHRASE, sys.argv[3])