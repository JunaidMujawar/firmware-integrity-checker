# Firmware Integrity Checker

A Python-based firmware verification system that detects tampering and corruption using SHA-256 hashing and RSA-PSS digital signatures.

## 

Firmware Integrity Checker verifies that a firmware file is:
- Unmodified.
- Signed by the legitimate vendor.
- Safe to trust before installation.

It uses:
- SHA-256 for integrity checking.
- RSA-PSS signatures for authenticity and non-repudiation.
- Python `cryptography` library for secure implementation.

## Features

- Generates RSA-3072 key pairs.
- Signs firmware with vendor private key.
- Verifies firmware using public key.
- Detects tampered, forged, or replaced firmware.
- Includes tamper simulation for demo and testing.
- CLI-based workflow for easy demonstration.

## Folder Structure

```text
firmware-integrity-checker/
├── src/
│   ├── keygen.py
│   ├── hash_utils.py
│   ├── sign_firmware.py
│   ├── verify_firmware.py
│   └── tamper_sim.py
├── keys/
├── firmware/
├── signatures/
├── tests/
├── docs/
├── requirements.txt
├── README.md
└── .gitignore
```

## Prerequisites

- Python 3.11 or later
- Git
- VS Code or any code editor

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-username/firmware-integrity-checker.git
cd firmware-integrity-checker
```

### 2. Create a virtual environment
```bash
python -m venv .venv
```

### 3. Activate the virtual environment
```bash
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

### 1. Generate RSA key pair
```bash
python src/keygen.py
```

This creates:
- `keys/private_key.pem`
- `keys/public_key.pem`

### 2. Create sample firmware
```bash
python -c "import os; open('firmware/sample.bin','wb').write(os.urandom(1048576))"
```

### 3. Sign the firmware
```bash
python src/sign_firmware.py firmware/sample.bin keys/private_key.pem signatures/sample.sig
```

### 4. Verify the firmware
```bash
python src/verify_firmware.py firmware/sample.bin signatures/sample.sig keys/public_key.pem
```

Expected output:
```text
Verification: PASSED
```

### 5. Run tamper simulation
```bash
python src/tamper_sim.py
```

Expected cases:
- Baseline firmware: PASS
- Bit-flipped firmware: FAIL
- Reused signature on forged firmware: FAIL
- Attacker-generated keypair: FAIL

## Security Design

The system separates vendor-side and device-side trust:

- The vendor keeps the private key.
- The device stores only the public key.
- Firmware is signed before distribution.
- Verification happens before flashing or installation.

This design ensures that attackers cannot forge valid firmware without the vendor's private key.

## Demo Workflow

1. Project structure.
2. Generate key pair.
3. Create sample firmware.
4. Sign firmware.
5. Verify original firmware.
6. Tamper with firmware.
7. Verify tampered firmware and show failure.
8. Run tamper simulation cases.
9. Why RSA-PSS and SHA-256 are used.

## Limitations

This prototype does not implement:
- Anti-rollback protection.
- Hardware root of trust.
- HSM-backed signing.
- Runtime integrity monitoring.

These are recommended future improvements.

## Future Improvements

- Add firmware version checking.
- Store public key in secure hardware.
- Support signed metadata manifests.
- Add web UI for upload and verification.
- Add CI tests for automatic validation.

## Team Contributions

- Key generation and signing.
- Verification and tamper testing.
- Report writing and presentation.
- GitHub repository management.

## License

For academic use only.
