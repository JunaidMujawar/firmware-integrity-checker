import hashlib

CHUNK_SIZE = 8192

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file_path(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def sha256_file_obj(file_obj) -> str:
    digest = hashlib.sha256()
    file_obj.seek(0)
    while True:
        chunk = file_obj.read(CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    file_obj.seek(0)
    return digest.hexdigest()