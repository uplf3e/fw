import secrets
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from .config import DB_PATH, DATA_DIR, ADMIN_CREDENTIALS_FILE

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT UNIQUE NOT NULL,
    owner_id     INTEGER NOT NULL,
    method       TEXT NOT NULL,
    url          TEXT NOT NULL,
    req_headers  TEXT NOT NULL,
    status_code  INTEGER,
    resp_headers TEXT,
    resp_body    TEXT,
    error        TEXT,
    hits         INTEGER NOT NULL DEFAULT 0,
    last_hit     TEXT,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    path        TEXT,
    status_code INTEGER,
    ts          TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    _add_column("requests", "hits", "INTEGER NOT NULL DEFAULT 0")
    _add_column("requests", "last_hit", "TEXT")
    _add_column("access_log", "path", "TEXT")
    ensure_default_admin()


def _add_column(table: str, col: str, definition: str) -> None:
    conn = get_conn()
    existing = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
    if col not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")
        conn.commit()
    conn.close()


def ensure_default_admin():
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if count == 0:
        uname = f"admin_{secrets.token_hex(3)}"
        pwd = secrets.token_urlsafe(12)
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) "
            "VALUES (?, ?, 1, ?)",
            (uname, generate_password_hash(pwd), now()),
        )
        conn.commit()
        creds = f"username: {uname}\npassword: {pwd}\n"
        ADMIN_CREDENTIALS_FILE.write_text(creds, encoding="utf-8")
        print("=" * 40)
        print("DEFAULT ADMIN ACCOUNT CREATED")
        print(creds)
        print("Saved to:", ADMIN_CREDENTIALS_FILE)
        print("=" * 40)
        conn.close()
        return uname, pwd
    conn.close()
    return None


def create_user(username: str, password: str, is_admin: int = 0) -> int:
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, is_admin, created_at) "
        "VALUES (?, ?, ?, ?)",
        (username, generate_password_hash(password), is_admin, now()),
    )
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


def verify_user(username: str, password: str):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password):
        return row
    return None


def get_user(uid: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def list_users():
    conn = get_conn()
    rows = conn.execute("SELECT id, username, is_admin, created_at FROM users").fetchall()
    conn.close()
    return rows


def insert_request(token, owner_id, method, url, req_headers, result):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO requests "
        "(token, owner_id, method, url, req_headers, status_code, resp_headers, "
        " resp_body, error, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            token,
            owner_id,
            method,
            url,
            req_headers,
            result.get("status_code"),
            result.get("resp_headers"),
            result.get("resp_body"),
            result.get("error"),
            now(),
        ),
    )
    rid = cur.lastrowid
    conn.commit()
    conn.close()
    return rid


def get_request_by_token(token: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM requests WHERE token = ?", (token,)).fetchone()
    conn.close()
    return row


def list_requests_by_owner(owner_id: int):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, token, method, url, status_code, hits, last_hit, created_at "
        "FROM requests WHERE owner_id = ? ORDER BY id DESC",
        (owner_id,),
    ).fetchall()
    conn.close()
    return rows


def record_access(token: str, ip: str, ua: str, path: str, status_code) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE requests SET hits = hits + 1, last_hit = ? WHERE token = ?",
        (now(), token),
    )
    conn.execute(
        "INSERT INTO access_log (token, ip, user_agent, path, status_code, ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (token, ip, ua, path, status_code, now()),
    )
    conn.commit()
    conn.close()


def get_access_log(token: str, limit: int = 50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT ip, user_agent, path, status_code, ts FROM access_log "
        "WHERE token = ? ORDER BY id DESC LIMIT ?",
        (token, limit),
    ).fetchall()
    conn.close()
    return rows
