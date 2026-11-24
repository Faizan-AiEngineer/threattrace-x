import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get("TTX_DATA_DIR", ROOT / "runtime")).resolve()
VAULT = DATA / "vault"
DB_URL = os.environ.get(
    "TTX_DATABASE_URL", f"sqlite:///{(DATA / 'threattrace.sqlite3').as_posix()}"
)
MAX_BYTES = int(os.environ.get("TTX_MAX_UPLOAD_MIB", "20")) * 1024 * 1024
CASE_EVENT_LIMIT = 100_000
CASE_EVIDENCE_LIMIT = 200
CASE_BYTES_LIMIT = 128 * 1024 * 1024
SESSION_HOURS = int(os.environ.get("TTX_SESSION_HOURS", "8"))
SECURE_COOKIE = os.environ.get("TTX_SECURE_COOKIE") == "1"
ORIGINS = os.environ.get(
    "TTX_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
).split(",")
