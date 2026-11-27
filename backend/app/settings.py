import os
from pathlib import Path
from urllib.parse import urlsplit

VERSION = "0.2.0"
ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get("TTX_DATA_DIR", ROOT / "runtime")).resolve()
VAULT = DATA / "vault"
LOCAL_DB_URL = f"sqlite:///{(DATA / 'threattrace.sqlite3').as_posix()}"
DB_URL = os.environ.get("TTX_DATABASE_URL", LOCAL_DB_URL)
DEMO_PROFILE = DATA / ".synthetic-demo"
LOOPBACK_CLIENTS = {"127.0.0.1", "::1"}
MAX_BYTES = int(os.environ.get("TTX_MAX_UPLOAD_MIB", "20")) * 1024 * 1024
CASE_EVENT_LIMIT = 100_000
CASE_EVIDENCE_LIMIT = 200
CASE_BYTES_LIMIT = 128 * 1024 * 1024
SESSION_HOURS = int(os.environ.get("TTX_SESSION_HOURS", "8"))
SECURE_COOKIE = os.environ.get("TTX_SECURE_COOKIE") == "1"
ORIGINS = os.environ.get(
    "TTX_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
).split(",")


def validate_demo_configuration():
    if DB_URL != LOCAL_DB_URL:
        raise ValueError("The demo uses the SQLite database in its own data directory.")
    for origin in ORIGINS:
        try:
            url = urlsplit(origin)
            if (
                url.scheme not in {"http", "https"}
                or url.hostname not in LOOPBACK_CLIENTS | {"localhost"}
                or url.username is not None
                or url.path
                or url.query
                or url.fragment
            ):
                raise ValueError
            _ = url.port
        except ValueError as error:
            raise ValueError("The demo requires loopback browser origins.") from error
