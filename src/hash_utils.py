import hashlib

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
    import sys
    print(sha256_of_file(sys.argv[1]))