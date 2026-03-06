"""
storage.py — Local file storage (R2 will be added later)
Files are saved in a local `uploads/` folder
"""
import os

UPLOAD_DIR = "uploads"
os.makedirs(f"{UPLOAD_DIR}/originals", exist_ok=True)
os.makedirs(f"{UPLOAD_DIR}/sanitized", exist_ok=True)


def upload_file(file_bytes: bytes, r2_key: str, content_type: str = "application/octet-stream") -> str:
    """Save file locally. r2_key used as relative path."""
    full_path = os.path.join(UPLOAD_DIR, r2_key)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "wb") as f:
        f.write(file_bytes)
    return r2_key


def download_file(r2_key: str) -> bytes:
    """Read file from local storage."""
    full_path = os.path.join(UPLOAD_DIR, r2_key)
    with open(full_path, "rb") as f:
        return f.read()


def get_presigned_url(r2_key: str, expires_in: int = 3600) -> str:
    """Not applicable for local storage — return local path."""
    return os.path.join(UPLOAD_DIR, r2_key)


def delete_file(r2_key: str):
    full_path = os.path.join(UPLOAD_DIR, r2_key)
    if os.path.exists(full_path):
        os.remove(full_path)


def get_content_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    mapping = {
        "pdf":  "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "sql":  "text/plain",
        "csv":  "text/csv",
        "txt":  "text/plain",
        "json": "application/json",
        "png":  "image/png",
        "jpg":  "image/jpeg",
        "jpeg": "image/jpeg",
    }
    return mapping.get(ext, "application/octet-stream")
