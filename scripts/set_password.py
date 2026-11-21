"""Change a user's password (deployment utility — run on the server, not via the web).

Usage:  python scripts/set_password.py <username> <new-password>
Inside Docker:  docker compose exec aegis python scripts/set_password.py dana '...'
"""
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aegis import db, auth, audit  # noqa: E402


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    username, password = sys.argv[1], sys.argv[2]
    if len(password) < 12:
        print("Refused: use at least 12 characters for a public deployment.")
        sys.exit(1)
    db.init_db()
    row = db.conn().execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if row is None:
        print(f"No such user: {username}")
        sys.exit(1)
    salt = os.urandom(16)
    pw_hash = auth._hash_pw(password, salt)
    db.conn().execute("UPDATE users SET pw_hash=?, salt=?, must_change=0 WHERE id=?",
                      (pw_hash, salt.hex(), row["id"]))
    db.conn().commit()
    audit.record("password_changed", {"username": username, "via": "set_password script"})
    print(f"Password updated for {username} (forced-change flag cleared).")


if __name__ == "__main__":
    main()