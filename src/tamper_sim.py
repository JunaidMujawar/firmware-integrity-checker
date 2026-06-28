from pathlib import Path
import os
import shutil
from keygen import generate_keypair
from sign_firmware import sign_firmware
from verify_firmware import verify_firmware

BASE = Path(__file__).resolve().parents[1]
FW = BASE / "firmware" / "sample.bin"
KEYS = BASE / "keys"
SIGS = BASE / "signatures"
TESTS = BASE / "tests"
PASSPHRASE = b"change-this-passphrase"

def make_sample_firmware():
    FW.parent.mkdir(exist_ok=True)
    if not FW.exists():
        FW.write_bytes(os.urandom(1024 * 1024))

def flip_byte(file_path, pos=100):
    data = bytearray(Path(file_path).read_bytes())
    data[pos] ^= 0xFF
    Path(file_path).write_bytes(data)

def main():
    for p in [KEYS, SIGS, TESTS]:
        p.mkdir(exist_ok=True)

    make_sample_firmware()

    generate_keypair(KEYS / "private_key.pem", KEYS / "public_key.pem", PASSPHRASE)
    sign_firmware(str(FW), str(KEYS / "private_key.pem"), PASSPHRASE, str(SIGS / "sample.sig"))

    result1 = verify_firmware(str(FW), str(SIGS / "sample.sig"), str(KEYS / "public_key.pem"))
    print("CASE 1 baseline:", "PASS" if result1 else "FAIL")

    tampered = TESTS / "tampered.bin"
    shutil.copy(FW, tampered)
    flip_byte(tampered)
    result2 = verify_firmware(str(tampered), str(SIGS / "sample.sig"), str(KEYS / "public_key.pem"))
    print("CASE 2 bit flip:", "PASS" if result2 else "FAIL")

    forged = TESTS / "forged.bin"
    forged.write_bytes(os.urandom(FW.stat().st_size))
    result3 = verify_firmware(str(forged), str(SIGS / "sample.sig"), str(KEYS / "public_key.pem"))
    print("CASE 3 forged reused sig:", "PASS" if result3 else "FAIL")

    attacker_priv = KEYS / "attacker_private.pem"
    attacker_pub = KEYS / "attacker_public.pem"
    generate_keypair(attacker_priv, attacker_pub, b"attackerpass")
    attacker_sig = SIGS / "attacker.sig"
    sign_firmware(str(forged), str(attacker_priv), b"attackerpass", str(attacker_sig))
    result4 = verify_firmware(str(forged), str(attacker_sig), str(KEYS / "public_key.pem"))
    print("CASE 4 attacker key:", "PASS" if result4 else "FAIL")

if __name__ == "__main__":
    main()