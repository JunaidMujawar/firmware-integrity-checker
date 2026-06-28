from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def verify_firmware(firmware_path: str, signature_path: str, public_key_path: str) -> bool:
    firmware_data = Path(firmware_path).read_bytes()
    signature = Path(signature_path).read_bytes()
    public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())

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
        return True
    except InvalidSignature:
        return False

if __name__ == "__main__":
    import sys
    ok = verify_firmware(sys.argv[1], sys.argv[2], sys.argv[3])
    print("Verification: PASSED" if ok else "Verification: FAILED")
    raise SystemExit(0 if ok else 1)