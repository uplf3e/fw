import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(
    os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
    or os.environ.get("DATA_DIR")
    or (BASE_DIR / "data")
)
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "app.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
APP_NAME = "RedirectVPNspoof"
ADMIN_CREDENTIALS_FILE = DATA_DIR / "admin_credentials.txt"
