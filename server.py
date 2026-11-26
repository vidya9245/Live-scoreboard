import hashlib
import hmac
import http.cookies
import http.server
import json
import os
import secrets
import socket
import sqlite3
import threading
import time
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scoreboard.db")
HOST = "127.0.0.1"
PORT = 8080
SESSION_COOKIE = "sb_session"
SESSION_TTL_SECONDS = 30 * 24 * 3600  # 30 days
PBKDF2_ITERATIONS = 200000

DB_LOCK = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}


def init_db():
    with DB_LOCK:
        conn = get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    username_lower TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at INTEGER,
                    expires_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS categories (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    created_at INTEGER,
                    updated_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS scoreboards (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL DEFAULT '',
                    category_id TEXT,
                    name TEXT NOT NULL,
                    format TEXT DEFAULT 'universal',
                    unit TEXT DEFAULT '',
                    participants_json TEXT DEFAULT '[]',
                    custom_columns_json TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'ongoing',
                    count INTEGER DEFAULT 0,
                    latest_score INTEGER,
                    latest_median REAL,
                    latest_mean REAL,
                    created_at INTEGER,
                    updated_at INTEGER,
                    completed_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS board_streams (
                    board_id TEXT PRIMARY KEY,
                    entries_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS user_meta (
                    user_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (user_id, key)
                );
                """
            )
            # Safe migration if pre-auth tables exist without user_id
            if "user_id" not in _table_columns(conn, "categories"):
                conn.execute("ALTER TABLE categories ADD COLUMN user_id TEXT NOT NULL DEFAULT ''")
            if "user_id" not in _table_columns(conn, "scoreboards"):
                conn.execute("ALTER TABLE scoreboards ADD COLUMN user_id TEXT NOT NULL DEFAULT ''")
            conn.commit()
        finally:
            conn.close()


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, expected_hash_hex):
    _, actual_hex = hash_password(password, salt_hex)
    return hmac.compare_digest(actual_hex, expected_hash_hex)


def row_to_user(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "displayName": row["display_name"],
        "createdAt": row["created_at"],
    }


def row_to_category(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"] or "",
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def row_to_scoreboard(row):
    return {
        "id": row["id"],
        "categoryId": row["category_id"],
        "name": row["name"],
        "format": row["format"] or "universal",
        "unit": row["unit"] or "",
        "participants": json.loads(row["participants_json"] or "[]"),
        "customColumns": json.loads(row["custom_columns_json"] or "[]"),
        "status": row["status"] or "ongoing",
        "count": row["count"] or 0,
        "latestScore": row["latest_score"],
        "latestMedian": row["latest_median"],
        "latestMean": row["latest_mean"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "completedAt": row["completed_at"],
    }


class ScoreboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def log_message(self, format, *args):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()

    def _send_json(self, status, data, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8"))

    def _get_session_token(self):
        cookie_hdr = self.headers.get("Cookie", "")
        if not cookie_hdr:
            return None
        c = http.cookies.SimpleCookie()
        try:
            c.load(cookie_hdr)
        except Exception:
            return None
        morsel = c.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _get_current_user(self):
        token = self._get_session_token()
        if not token:
            return None
        now = int(time.time())
        with DB_LOCK:
            conn = get_conn()
            try:
                row = conn.execute(
                    """
                    SELECT u.* FROM sessions s
                    JOIN users u ON u.id = s.user_id
                    WHERE s.token = ? AND s.expires_at > ?
                    """,
                    (token, now),
                ).fetchone()
                if not row:
                    return None
                return row_to_user(row)
            finally:
                conn.close()

    def _create_session_cookie(self, user_id):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + SESSION_TTL_SECONDS
        with DB_LOCK:
            conn = get_conn()
            try:
                conn.execute(
                    "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    (token, user_id, now, expires),
                )
                conn.commit()
            finally:
                conn.close()
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"

    def _require_user(self):
        user = self._get_current_user()
        if not user:
            self._send_json(401, {"error": "Authentication required"})
            return None
        return user

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            return self._send_json(200, {"ok": True, "db": "sqlite3", "auth": True})

        if path == "/api/auth/me":
            user = self._get_current_user()
            return self._send_json(200, {"authenticated": bool(user), "user": user})

        if path == "/api/workspace":
            user = self._require_user()
            if not user:
                return
            uid = user["id"]
            with DB_LOCK:
                conn = get_conn()
                try:
                    cats = [
                        row_to_category(r)
                        for r in conn.execute(
                            "SELECT * FROM categories WHERE user_id = ? ORDER BY created_at ASC", (uid,)
                        ).fetchall()
                    ]
                    boards = [
                        row_to_scoreboard(r)
                        for r in conn.execute(
                            "SELECT * FROM scoreboards WHERE user_id = ? ORDER BY updated_at DESC", (uid,)
                        ).fetchall()
                    ]
                    meta_row = conn.execute(
                        "SELECT value FROM user_meta WHERE user_id = ? AND key = 'activeBoardId'", (uid,)
                    ).fetchone()
                    active_id = json.loads(meta_row["value"]) if meta_row and meta_row["value"] is not None else None
                finally:
                    conn.close()
            return self._send_json(200, {
                "categories": cats,
                "scoreboards": boards,
                "activeBoardId": active_id,
                "backend": "SQLite",
                "user": user,
            })

        if path.startswith("/api/scoreboards/") and path.endswith("/stream"):
            user = self._require_user()
            if not user:
                return
            parts = path.split("/")
            if len(parts) == 5:
                board_id = urllib.parse.unquote(parts[3])
                with DB_LOCK:
                    conn = get_conn()
                    try:
                        owner_row = conn.execute(
                            "SELECT user_id FROM scoreboards WHERE id = ?", (board_id,)
                        ).fetchone()
                        if not owner_row or owner_row["user_id"] != user["id"]:
                            return self._send_json(404, {"error": "Scoreboard not found"})
                        row = conn.execute(
                            "SELECT entries_json FROM board_streams WHERE board_id = ?", (board_id,)
                        ).fetchone()
                        entries = json.loads(row["entries_json"]) if row else []
                    finally:
                        conn.close()
                return self._send_json(200, {"boardId": board_id, "entries": entries})

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            payload = self._read_json()
        except Exception:
            return self._send_json(400, {"error": "Invalid JSON"})

        if path == "/api/auth/signup":
            username = str(payload.get("username", "")).strip()
            display_name = str(payload.get("displayName", "")).strip() or username
            password = str(payload.get("password", ""))

            if len(username) < 3 or len(username) > 40:
                return self._send_json(400, {"error": "Username must be between 3 and 40 characters."})
            if len(password) < 6:
                return self._send_json(400, {"error": "Password must be at least 6 characters."})

            username_lower = username.lower()
            user_id = f"usr_{secrets.token_hex(8)}"
            salt_hex, hash_hex = hash_password(password)
            now = int(time.time() * 1000)

            with DB_LOCK:
                conn = get_conn()
                try:
                    existing = conn.execute(
                        "SELECT id FROM users WHERE username_lower = ?", (username_lower,)
                    ).fetchone()
                    if existing:
                        return self._send_json(409, {"error": "That username is already taken."})

                    conn.execute(
                        """
                        INSERT INTO users (id, username, username_lower, display_name, password_salt, password_hash, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (user_id, username, username_lower, display_name, salt_hex, hash_hex, now),
                    )
                    conn.commit()
                finally:
                    conn.close()

            cookie = self._create_session_cookie(user_id)
            user = {"id": user_id, "username": username, "displayName": display_name, "createdAt": now}
            return self._send_json(201, {"user": user}, [("Set-Cookie", cookie)])

        if path == "/api/auth/login":
            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            if not username or not password:
                return self._send_json(400, {"error": "Please enter both username and password."})

            with DB_LOCK:
                conn = get_conn()
                try:
                    row = conn.execute(
                        "SELECT * FROM users WHERE username_lower = ?", (username.lower(),)
                    ).fetchone()
                finally:
                    conn.close()

            if not row or not verify_password(password, row["password_salt"], row["password_hash"]):
                return self._send_json(401, {"error": "Invalid username or password."})

            cookie = self._create_session_cookie(row["id"])
            return self._send_json(200, {"user": row_to_user(row)}, [("Set-Cookie", cookie)])

        if path == "/api/auth/logout":
            token = self._get_session_token()
            if token:
                with DB_LOCK:
                    conn = get_conn()
                    try:
                        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                        conn.commit()
                    finally:
                        conn.close()
            clear_cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            return self._send_json(200, {"ok": True}, [("Set-Cookie", clear_cookie)])

        return self._send_json(404, {"error": "Not found"})

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        user = self._require_user()
        if not user:
            return
        uid = user["id"]

        try:
            payload = self._read_json()
        except Exception:
            return self._send_json(400, {"error": "Invalid JSON"})

        if path == "/api/meta/active-board":
            val = json.dumps(payload.get("activeBoardId"))
            with DB_LOCK:
                conn = get_conn()
                try:
                    conn.execute(
                        """
                        INSERT INTO user_meta (user_id, key, value) VALUES (?, 'activeBoardId', ?)
                        ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value
                        """,
                        (uid, val),
                    )
                    conn.commit()
                finally:
                    conn.close()
            return self._send_json(200, {"ok": True})

        if path.startswith("/api/categories/"):
            cat_id = urllib.parse.unquote(path[len("/api/categories/"):])
            with DB_LOCK:
                conn = get_conn()
                try:
                    existing = conn.execute("SELECT user_id FROM categories WHERE id = ?", (cat_id,)).fetchone()
                    if existing and existing["user_id"] != uid:
                        return self._send_json(403, {"error": "Forbidden"})
                    conn.execute(
                        """
                        INSERT INTO categories (id, user_id, name, description, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            name = excluded.name,
                            description = excluded.description,
                            updated_at = excluded.updated_at
                        WHERE categories.user_id = excluded.user_id
                        """,
                        (
                            cat_id,
                            uid,
                            str(payload.get("name", "")).strip(),
                            str(payload.get("description", "")).strip(),
                            payload.get("createdAt"),
                            payload.get("updatedAt"),
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
            return self._send_json(200, {"ok": True})

        if path.startswith("/api/scoreboards/") and path.endswith("/stream"):
            parts = path.split("/")
            if len(parts) == 5:
                board_id = urllib.parse.unquote(parts[3])
                entries = payload.get("entries", [])
                entries_json = json.dumps(entries)
                with DB_LOCK:
                    conn = get_conn()
                    try:
                        owner_row = conn.execute(
                            "SELECT user_id FROM scoreboards WHERE id = ?", (board_id,)
                        ).fetchone()
                        if not owner_row or owner_row["user_id"] != uid:
                            return self._send_json(403, {"error": "Forbidden"})
                        conn.execute(
                            """
                            INSERT INTO board_streams (board_id, entries_json)
                            VALUES (?, ?)
                            ON CONFLICT(board_id) DO UPDATE SET entries_json = excluded.entries_json
                            """,
                            (board_id, entries_json),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                return self._send_json(200, {"ok": True})

        if path.startswith("/api/scoreboards/"):
            board_id = urllib.parse.unquote(path[len("/api/scoreboards/"):])
            with DB_LOCK:
                conn = get_conn()
                try:
                    existing = conn.execute("SELECT user_id FROM scoreboards WHERE id = ?", (board_id,)).fetchone()
                    if existing and existing["user_id"] != uid:
                        return self._send_json(403, {"error": "Forbidden"})
                    conn.execute(
                        """
                        INSERT INTO scoreboards (
                            id, user_id, category_id, name, format, unit,
                            participants_json, custom_columns_json,
                            status, count, latest_score, latest_median, latest_mean,
                            created_at, updated_at, completed_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            category_id = excluded.category_id,
                            name = excluded.name,
                            format = excluded.format,
                            unit = excluded.unit,
                            participants_json = excluded.participants_json,
                            custom_columns_json = excluded.custom_columns_json,
                            status = excluded.status,
                            count = excluded.count,
                            latest_score = excluded.latest_score,
                            latest_median = excluded.latest_median,
                            latest_mean = excluded.latest_mean,
                            updated_at = excluded.updated_at,
                            completed_at = excluded.completed_at
                        WHERE scoreboards.user_id = excluded.user_id
                        """,
                        (
                            board_id,
                            uid,
                            payload.get("categoryId"),
                            str(payload.get("name", "")).strip(),
                            str(payload.get("format", "universal")),
                            str(payload.get("unit", "")),
                            json.dumps(payload.get("participants", [])),
                            json.dumps(payload.get("customColumns", [])),
                            str(payload.get("status", "ongoing")),
                            int(payload.get("count") or 0),
                            payload.get("latestScore"),
                            payload.get("latestMedian"),
                            payload.get("latestMean"),
                            payload.get("createdAt"),
                            payload.get("updatedAt"),
                            payload.get("completedAt"),
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
            return self._send_json(200, {"ok": True})

        return self._send_json(404, {"error": "Not found"})

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        user = self._require_user()
        if not user:
            return
        uid = user["id"]

        if path.startswith("/api/categories/"):
            cat_id = urllib.parse.unquote(path[len("/api/categories/"):])
            with DB_LOCK:
                conn = get_conn()
                try:
                    conn.execute("DELETE FROM categories WHERE id = ? AND user_id = ?", (cat_id, uid))
                    conn.commit()
                finally:
                    conn.close()
            return self._send_json(200, {"ok": True})

        if path.startswith("/api/scoreboards/"):
            board_id = urllib.parse.unquote(path[len("/api/scoreboards/"):])
            with DB_LOCK:
                conn = get_conn()
                try:
                    cur = conn.execute("DELETE FROM scoreboards WHERE id = ? AND user_id = ?", (board_id, uid))
                    if cur.rowcount > 0:
                        conn.execute("DELETE FROM board_streams WHERE board_id = ?", (board_id,))
                    conn.commit()
                finally:
                    conn.close()
            return self._send_json(200, {"ok": True})

        return self._send_json(404, {"error": "Not found"})


class ThreadingHTTPServerV6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    init_db()
    servers = []

    srv4 = http.server.ThreadingHTTPServer((HOST, PORT), ScoreboardHandler)
    servers.append(srv4)

    try:
        srv6 = ThreadingHTTPServerV6(("::1", PORT), ScoreboardHandler)
        servers.append(srv6)
        t6 = threading.Thread(target=srv6.serve_forever, daemon=True)
        t6.start()
    except OSError:
        pass

    print(f"Live Scoreboard running at http://localhost:{PORT} and http://{HOST}:{PORT} (SQLite DB: {DB_PATH})", flush=True)
    try:
        srv4.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            try:
                s.server_close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
