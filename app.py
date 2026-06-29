import streamlit as st
from pathlib import Path

from backend.key_manager import generate_keypair, load_private_key, load_public_key
from backend.signer import sign_firmware_bytes
from backend.verifier import verify_firmware_bytes
from backend.crypto_utils import sha256_bytes
from backend.tamper_tests import run_tamper_tests

st.set_page_config(page_title="Firmware Integrity Checker", layout="wide")

DATA_DIR = Path("data")
KEY_DIR = DATA_DIR / "keys"
SIG_DIR = DATA_DIR / "signatures"
FW_DIR = DATA_DIR / "firmware"

for d in [DATA_DIR, KEY_DIR, SIG_DIR, FW_DIR]:
    d.mkdir(parents=True, exist_ok=True)

PASSPHRASE = b"change-this-passphrase"

if "firmware_bytes" not in st.session_state:
    st.session_state.firmware_bytes = None
if "signature_bytes" not in st.session_state:
    st.session_state.signature_bytes = None
if "public_key_bytes" not in st.session_state:
    st.session_state.public_key_bytes = None
if "private_key_bytes" not in st.session_state:
    st.session_state.private_key_bytes = None

st.title("Firmware Integrity Checker")
st.caption("A Streamlit-based cryptographic dashboard for firmware signing and verification")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Overview",
    "Key Management",
    "Sign Firmware",
    "Verify Firmware",
    "Tamper Test"
])

with tab1:
    st.subheader("Project Overview")
    st.write(
        "This application demonstrates secure firmware integrity checking using SHA-256 hashing "
        "and RSA-PSS digital signatures. The private key remains on the vendor side, while the "
        "public key is used for verification."
    )
    st.info("Goal: show integrity, authenticity, and non-repudiation in a clean visual workflow.")

with tab2:
    st.subheader("Key Management")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("Generate RSA Keys"):
            private_path, public_path = generate_keypair(
                str(KEY_DIR / "private_key.pem"),
                str(KEY_DIR / "public_key.pem"),
                PASSPHRASE
            )
            st.success("Key pair generated successfully.")
            st.write(f"Private key saved to: `{private_path}`")
            st.write(f"Public key saved to: `{public_path}`")

    with col2:
        pub_file = st.file_uploader("Upload Public Key", type=["pem"], key="pub_upload")
        priv_file = st.file_uploader("Upload Private Key", type=["pem"], key="priv_upload")

        if pub_file is not None:
            st.session_state.public_key_bytes = pub_file.read()
            st.success("Public key loaded.")

        if priv_file is not None:
            st.session_state.private_key_bytes = priv_file.read()
            st.warning("Private key loaded locally for signing only.")

with tab3:
    st.subheader("Sign Firmware")
    firmware_file = st.file_uploader("Upload Firmware File", type=["bin", "img", "fw"], key="firmware_upload")

    if firmware_file is not None:
        st.session_state.firmware_bytes = firmware_file.read()
        fw_hash = sha256_bytes(st.session_state.firmware_bytes)
        st.code(fw_hash, language="text")
        st.write("Firmware hash displayed above.")

    if st.button("Sign Firmware"):
        if st.session_state.firmware_bytes is None:
            st.error("Please upload firmware first.")
        elif st.session_state.private_key_bytes is None:
            st.error("Please upload the private key first.")
        else:
            with st.spinner("Signing firmware..."):
                private_key = load_private_key(st.session_state.private_key_bytes, PASSPHRASE)
                firmware_hash, signature = sign_firmware_bytes(st.session_state.firmware_bytes, private_key)

                SIG_DIR.mkdir(parents=True, exist_ok=True)
                sig_path = SIG_DIR / "firmware.sig"
                sig_path.write_bytes(signature)

                st.success("Firmware signed successfully.")
                st.write(f"SHA-256: `{firmware_hash}`")
                st.write(f"Signature saved to: `{sig_path}`")
                st.session_state.signature_bytes = signature

with tab4:
    st.subheader("Verify Firmware")
    verify_fw = st.file_uploader("Upload Firmware for Verification", type=["bin", "img", "fw"], key="verify_fw")
    verify_sig = st.file_uploader("Upload Signature File", type=["sig"], key="verify_sig")
    verify_pub = st.file_uploader("Upload Public Key File", type=["pem"], key="verify_pub")

    if st.button("Verify Firmware"):
        if verify_fw is None or verify_sig is None or verify_pub is None:
            st.error("Please upload firmware, signature, and public key.")
        else:
            firmware_bytes = verify_fw.read()
            signature_bytes = verify_sig.read()
            public_key = load_public_key(verify_pub.read())

            with st.spinner("Verifying firmware..."):
                ok, fw_hash, msg = verify_firmware_bytes(firmware_bytes, signature_bytes, public_key)

                st.write(f"SHA-256: `{fw_hash}`")
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

with tab5:
    st.subheader("Tamper Test")
    tamper_upload = st.file_uploader("Upload Baseline Firmware", type=["bin", "img", "fw"], key="tamper_upload")

    if st.button("Run Tamper Evaluation"):
        if tamper_upload is None:
            st.error("Please upload a firmware file first.")
        else:
            firmware_bytes = tamper_upload.read()
            results = run_tamper_tests(firmware_bytes, PASSPHRASE)

            st.table(
                [{"Test Case": name, "Result": "PASS" if ok else "FAIL"} for name, ok in results]
            )
            st.write("Baseline should pass; tampered or forged cases should fail.")