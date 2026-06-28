from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

PASSPHRASE = b"change-this-passphrase"

def sign_firmware(firmware_path: str, private_key_path: str, passphrase: bytes, signature_out_path: str):
    firmware_data = Path(firmware_path).read_bytes()
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=passphrase
    )

    signature = private_key.sign(
        firmware_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    Path(signature_out_path).write_bytes(signature)
    print(f"Signature written to {signature_out_path}")

if __name__ == "__main__":
    import sys
    sign_firmware(sys.argv[1], sys.argv[2], PASSPHRASE, sys.argv[3])