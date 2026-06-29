from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(private_path: str, public_path: str, passphrase: bytes):
    private_path = Path(private_path)
    public_path = Path(public_path)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

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

    return str(private_path), str(public_path)

def load_private_key(private_key_bytes: bytes, passphrase: bytes):
    return serialization.load_pem_private_key(private_key_bytes, password=passphrase)

def load_public_key(public_key_bytes: bytes):
    return serialization.load_pem_public_key(public_key_bytes)