"""
Intentionally vulnerable Flask API demo.

DO NOT deploy this application. Every endpoint exists to demonstrate
common API security flaws for training and scanner evaluation.
"""

import json
import os
import sqlite3
import subprocess

import requests
from flask import Flask, jsonify, request

import config

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["DEBUG"] = config.DEBUG_MODE


def get_db():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            ssn TEXT
        );

        DELETE FROM users;
        INSERT INTO users (username, password, email, role, ssn) VALUES
            ('alice', 'password123', 'alice@example.com', 'user', '111-22-3333'),
            ('bob', 'qwerty', 'bob@example.com', 'user', '222-33-4444'),
            ('admin', 'admin123', 'admin@example.com', 'admin', '999-88-7777');
        """
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify(
        {
            "name": "Vulnerable API Demo",
            "warning": "This application is intentionally insecure.",
            "endpoints": [
                "POST /api/login",
                "GET /api/users",
                "GET /api/users/<id>",
                "POST /api/users",
                "GET /api/search?q=",
                "GET /api/profile",
                "POST /api/fetch",
                "GET /api/files?path=",
                "POST /api/exec",
                "GET /api/admin",
                "GET /api/debug",
                "GET /api/echo?message=",
                "DELETE /api/users/<id>",
            ],
        }
    )


@app.route("/api/login", methods=["POST"])
def login():
    """SQL injection + weak credential handling."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Vulnerable: string concatenation in SQL query
    query = (
        "SELECT id, username, role, email FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    conn = get_db()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        conn.close()
        return jsonify({"error": str(exc), "query": query}), 500
    conn.close()

    if row:
        return jsonify(
            {
                "success": True,
                "user": dict(row),
                "token": config.API_TOKEN,
                "session_secret": config.SECRET_KEY,
            }
        )

    return jsonify({"success": False, "message": "Invalid credentials"}), 401


@app.route("/api/users", methods=["GET"])
def list_users():
    """Broken access control: no authentication required."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, email, role, password, ssn FROM users"
    ).fetchall()
    conn.close()
    return jsonify({"users": [dict(row) for row in rows]})


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """IDOR: any caller can read any user by ID."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, role, password, ssn FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(row))


@app.route("/api/users", methods=["POST"])
def create_user():
    """Mass assignment: accepts arbitrary fields including role."""
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password", "changeme")
    email = data.get("email", "")
    role = data.get("role", "user")
    ssn = data.get("ssn", "")

    if not username:
        return jsonify({"error": "username is required"}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password, email, role, ssn) VALUES (?, ?, ?, ?, ?)",
        (username, password, email, role, ssn),
    )
    conn.commit()
    user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    return jsonify({"id": user_id, "username": username, "role": role}), 201


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Missing authorization: anyone can delete users."""
    conn = get_db()
    cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    if cursor.rowcount == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"deleted": user_id})


@app.route("/api/search")
def search_users():
    """SQL injection via query parameter."""
    term = request.args.get("q", "")

    query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{term}%'"

    conn = get_db()
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return jsonify({"error": str(exc), "query": query}), 500
    conn.close()

    return jsonify({"results": [dict(row) for row in rows], "query": query})


@app.route("/api/profile")
def profile():
    """Broken authentication: trusts client-supplied user id header."""
    user_id = request.headers.get("X-User-Id")

    if not user_id:
        return jsonify({"error": "Missing X-User-Id header"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, role, password, ssn FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(row))


@app.route("/api/fetch", methods=["POST"])
def fetch_url():
    """SSRF: fetches arbitrary URLs supplied by the client."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return jsonify(
            {
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:5000],
            }
        )
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/api/files")
def read_file():
    """Path traversal: reads files from predictable locations."""
    path = request.args.get("path", "notes.txt")
    base_dir = os.path.join(os.path.dirname(__file__), "data")

    # Vulnerable: no normalization or sandboxing
    full_path = os.path.join(base_dir, path)

    try:
        with open(full_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError as exc:
        return jsonify({"error": str(exc), "attempted_path": full_path}), 404

    return jsonify({"path": path, "content": content})


@app.route("/api/exec", methods=["POST"])
def exec_command():
    """Command injection via unsanitized shell execution."""
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "localhost")

    # Vulnerable: passes user input directly to shell
    command = f"ping -c 1 {hostname}"
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )

    return jsonify(
        {
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    )


@app.route("/api/admin")
def admin_panel():
    """Broken access control: weak token check with default credentials."""
    token = request.args.get("token", "")

    if token == config.API_TOKEN or token == config.ADMIN_PASSWORD:
        return jsonify(
            {
                "admin": True,
                "secrets": {
                    "secret_key": config.SECRET_KEY,
                    "admin_password": config.ADMIN_PASSWORD,
                    "api_token": config.API_TOKEN,
                },
                "environment": dict(os.environ),
            }
        )

    return jsonify({"error": "Forbidden"}), 403


@app.route("/api/debug")
def debug_info():
    """Information disclosure: exposes internals without auth."""
    return jsonify(
        {
            "debug": config.DEBUG_MODE,
            "config": {
                "SECRET_KEY": config.SECRET_KEY,
                "ADMIN_PASSWORD": config.ADMIN_PASSWORD,
                "API_TOKEN": config.API_TOKEN,
                "DATABASE_PATH": config.DATABASE_PATH,
            },
            "request_headers": dict(request.headers),
            "server_env": {
                key: value
                for key, value in os.environ.items()
                if key.startswith(("PATH", "HOME", "USER", "FLASK", "PYTHON"))
            },
        }
    )


@app.route("/api/echo")
def echo():
    """Reflected XSS / unsafe output: returns unescaped user input."""
    message = request.args.get("message", "")
    return jsonify({"echo": message, "html": f"<p>{message}</p>"})


@app.errorhandler(Exception)
def handle_error(error):
    """Verbose error handling leaks stack traces and request data."""
    return jsonify(
        {
            "error": str(error),
            "type": error.__class__.__name__,
            "path": request.path,
            "method": request.method,
            "args": request.args.to_dict(),
            "json": request.get_json(silent=True),
            "headers": dict(request.headers),
        }
    ), 500


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)

    notes_path = os.path.join(os.path.dirname(__file__), "data", "notes.txt")
    if not os.path.exists(notes_path):
        with open(notes_path, "w", encoding="utf-8") as handle:
            handle.write("Internal note: rotate API token quarterly.\n")

    init_db()
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=True)
