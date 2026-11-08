import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE-THIS-SECRET-KEY-BEFORE-DEPLOYMENT")
    DATABASE = str(ROOT / "database" / "sentinelx.db")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
