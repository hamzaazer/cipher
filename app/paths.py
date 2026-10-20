"""Filesystem locations.

On Android, serious_python exports FLET_APP_STORAGE_DATA pointing at the app's
private data directory.  On desktop we use a per-user directory.  Tests always
set CIPHER_DATA_DIR to a temporary directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    override = os.getenv("CIPHER_DATA_DIR")
    if override:
        p = Path(override)
    elif os.getenv("FLET_APP_STORAGE_DATA"):
        p = Path(os.environ["FLET_APP_STORAGE_DATA"]) / "cipher"
    elif sys.platform == "win32":
        p = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "Cipher"
    else:
        p = Path(os.getenv("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "cipher"
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def db_path() -> Path:
    return data_dir() / "cipher.db"


def identity_path() -> Path:
    return data_dir() / "identity.json"
