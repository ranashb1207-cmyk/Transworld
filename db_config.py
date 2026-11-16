"""
Centralized Database & App Configuration
Loads settings from .env file if present, or falls back to environment variables / defaults.
"""
import os
from pathlib import Path

# Load .env manually without external dependency
env_path = Path(__file__).resolve().parent / '.env'
if env_path.exists():
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k not in os.environ:
                os.environ[k] = v

_db_password = os.environ.get("DB_PASSWORD")
if not _db_password:
    raise RuntimeError("DB_PASSWORD is missing. Add DB_PASSWORD=... to the .env file next to server.py.")

DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "transworlddatabase"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": _db_password,
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", 5432))
}

PORT = int(os.environ.get("PORT", 5000))
ALLOWED_ORIGIN = "http://localhost:5000"
