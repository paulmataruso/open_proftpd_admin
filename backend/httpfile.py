"""
backend/httpfile.py

Writes /etc/nginx/.htpasswd for HTTP basic auth.

Rules:
  - The first line of the existing .htpasswd (the shared public login,
    PUBLIC_HTTP_USERNAME) is
    preserved verbatim — it is NEVER modified or removed.
  - All other lines are replaced with the current enabled users on every sync.
  - nginx supports both $apr1$ (MD5) and $2y$ (bcrypt) in the same file.
  - Python's bcrypt produces $2b$ — we write $2y$ which is identical for nginx.
  - File is written atomically (temp file + rename) to avoid partial reads.
"""

import os
import tempfile
from sqlalchemy.orm import Session
from models import User
from config import settings


def _bcrypt_to_nginx(hash_str: str) -> str:
    """Convert Python bcrypt $2b$ prefix to nginx-compatible $2y$."""
    if hash_str.startswith("$2b$"):
        return "$2y$" + hash_str[4:]
    return hash_str


def regenerate_htpasswd(db: Session) -> int:
    """
    Rewrite .htpasswd with the protected entry first, then all enabled users.
    Returns the number of managed user lines written.
    """
    htpasswd_path = settings.htpasswd_path

    # Read the existing file to extract the protected first line
    protected_line = ""
    protected_username = ""
    try:
        with open(htpasswd_path, "r") as f:
            lines = f.read().splitlines()
            if lines:
                protected_line = lines[0]  # always preserve this verbatim
                protected_username = protected_line.split(":")[0]
    except FileNotFoundError:
        pass  # first run — file doesn't exist yet, no protected entry to preserve

    # Fetch all enabled users, excluding the protected entry's username
    query = db.query(User).filter(User.enabled == True)
    if protected_username:
        query = query.filter(User.username != protected_username)
    users = query.order_by(User.username).all()

    # Build the new file content
    content_lines = []
    if protected_line:
        content_lines.append(protected_line)

    for user in users:
        nginx_hash = _bcrypt_to_nginx(user.password_hash)
        content_lines.append(f"{user.username}:{nginx_hash}")

    content = "\n".join(content_lines) + "\n"

    # Atomic write — temp file in same directory then rename
    htpasswd_dir = os.path.dirname(htpasswd_path)
    fd, tmp_path = tempfile.mkstemp(dir=htpasswd_dir, prefix=".htpasswd.tmp.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, htpasswd_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise

    return len(users)
