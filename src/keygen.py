from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

BASE = Path(__file__).resolve().parents[1]
KEYS = BASE / "keys"
KEYS.mkdir(exist_ok=True)

PRIVATE_PATH = KEYS / "private_key.pem"
PUBLIC_PATH = KEYS / "public_key.pem"
PASSPHRASE = b"change-this-passphrase"

def generate_keypair(private_path=PRIVATE_PATH, public_path=PUBLIC_PATH, passphrase=PASSPHRASE):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
    )

    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"Generated {private_path}")
    print(f"Generated {public_path}")

if __name__ == "__main__":
    generate_keypair()