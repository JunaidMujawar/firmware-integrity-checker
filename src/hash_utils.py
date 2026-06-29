import hashlib
import sys

CHUNK_SIZE = 8192

def sha256_of_file(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python src/hash_utils.py <file_path>")
        raise SystemExit(1)

    file_path = sys.argv[1]
    print(f"[INFO] Hashing file: {file_path}")
    print(f"[INFO] SHA-256: {sha256_of_file(file_path)}")