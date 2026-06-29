from backend.signer import sign_firmware_bytes
from backend.verifier import verify_firmware_bytes
from backend.key_manager import generate_keypair, load_private_key, load_public_key

def flip_one_byte(data: bytes, index: int = 10) -> bytes:
    if len(data) == 0:
        return data
    index = min(index, len(data) - 1)
    modified = bytearray(data)
    modified[index] ^= 0xFF
    return bytes(modified)

def run_tamper_tests(firmware_bytes: bytes, passphrase: bytes):
    results = []

    private_key_path = "data/keys/private_key.pem"
    public_key_path = "data/keys/public_key.pem"
    generate_keypair(private_key_path, public_key_path, passphrase)

    with open(private_key_path, "rb") as f:
        private_key = load_private_key(f.read(), passphrase)

    with open(public_key_path, "rb") as f:
        public_key = load_public_key(f.read())

    fw_hash, sig = sign_firmware_bytes(firmware_bytes, private_key)
    ok, _, _ = verify_firmware_bytes(firmware_bytes, sig, public_key)
    results.append(("Baseline firmware", ok))

    tampered = flip_one_byte(firmware_bytes)
    ok, _, _ = verify_firmware_bytes(tampered, sig, public_key)
    results.append(("Bit-flip tamper", ok))

    forged = b"attacker malicious firmware" * 20
    ok, _, _ = verify_firmware_bytes(forged, sig, public_key)
    results.append(("Reused signature on forged firmware", ok))

    attacker_private_path = "data/keys/attacker_private.pem"
    attacker_public_path = "data/keys/attacker_public.pem"
    generate_keypair(attacker_private_path, attacker_public_path, b"attackerpass")

    with open(attacker_private_path, "rb") as f:
        attacker_private = load_private_key(f.read(), b"attackerpass")

    attacker_hash, attacker_sig = sign_firmware_bytes(forged, attacker_private)
    ok, _, _ = verify_firmware_bytes(forged, attacker_sig, public_key)
    results.append(("Attacker-generated keypair", ok))

    return results