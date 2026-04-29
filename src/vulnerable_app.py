"""
Vulnerable Flask Application - For SAST Demonstration

This application contains intentional security vulnerabilities for testing
automated security remediation with Snyk and Cursor CLI.

WARNING: DO NOT use this code in production!
"""

import ast
import html
import json
import os
import re
import sqlite3
import subprocess
from urllib.parse import unquote

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN", "")

# Allowlisted columns for dynamic WHERE clauses (identifiers cannot be bound as parameters in SQLite).
_USER_FILTER_COLUMNS = frozenset({"id", "name", "email", "password"})

_PING_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def _project_root():
    """Package directory parent (repo root when layout is project/src/...)."""
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _safe_cwd():
    """Current working directory, or project root if cwd is missing (e.g. deleted temp dir)."""
    try:
        return os.getcwd()
    except (FileNotFoundError, OSError):
        return _project_root()


def _safe_path_under(base_dir, user_path):
    """
    Resolve user_path under base_dir; return absolute path or None if invalid.
    Rejects '..', absolute paths, and paths that escape base_dir after normalization.
    """
    if not user_path or user_path != user_path.strip():
        return None
    if ".." in user_path or ".." in unquote(user_path):
        return None
    if os.path.isabs(user_path):
        return None
    if os.path.isabs(base_dir):
        root = os.path.abspath(base_dir)
    else:
        try:
            root = os.path.abspath(base_dir)
        except FileNotFoundError:
            root = os.path.normpath(os.path.join(_project_root(), base_dir))
    candidate = os.path.normpath(os.path.join(root, user_path))
    try:
        if os.path.commonpath([root, candidate]) != root:
            return None
    except ValueError:
        return None
    try:
        candidate = os.path.realpath(candidate)
        root_real = os.path.realpath(root)
        if candidate != root_real and not candidate.startswith(root_real + os.sep):
            return None
    except (FileNotFoundError, OSError):
        pass
    return candidate


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user/<user_id>")
def get_user(user_id):
    """
    VULNERABILITY: SQL Injection
    User input is directly concatenated into the SQL query.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/search")
def search_users():
    """
    VULNERABILITY: SQL Injection via string formatting
    User input from query parameter is interpolated into SQL.
    """
    name = request.args.get("name", "")
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{name}%",))

    users = cursor.fetchall()
    conn.close()

    return jsonify([dict(u) for u in users])


@app.route("/users/filter", methods=["POST"])
def filter_users():
    """
    VULNERABILITY: SQL Injection via direct string concatenation
    User input is directly concatenated into the SQL query without sanitization.
    """
    data = request.get_json()
    column = data.get("column", "name")
    value = data.get("value", "")

    if column not in _USER_FILTER_COLUMNS:
        return jsonify({"error": "Invalid column"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE {} = ?".format(column)
    cursor.execute(query, (value,))
    
    users = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])


@app.route("/execute", methods=["POST"])
def execute_command():
    """
    VULNERABILITY: Command Injection via os.system
    User input is directly passed to shell command.
    """
    data = request.get_json()
    filename = data.get("filename", "")

    safe_path = _safe_path_under(_safe_cwd(), filename)
    if safe_path is None:
        return jsonify({"error": "Invalid path"}), 400

    subprocess.run(["cat", "--", safe_path], capture_output=True, text=True, check=False)

    return jsonify({"status": "executed"})


@app.route("/process", methods=["POST"])
def process_file():
    """
    VULNERABILITY: Command Injection via subprocess with shell=True
    User input is passed to subprocess with shell enabled.
    """
    data = request.get_json()
    file_path = data.get("path", "")

    safe_path = _safe_path_under(_safe_cwd(), file_path)
    if safe_path is None:
        return jsonify({"error": "Invalid path"}), 400

    result = subprocess.run(
        ["wc", "-l", "--", safe_path],
        capture_output=True,
        text=True,
        check=False,
    )

    return jsonify({"output": result.stdout or result.stderr or ""})


@app.route("/read-file")
def read_file():
    """
    VULNERABILITY: Path Traversal
    User can escape the uploads directory using ../
    """
    filename = request.args.get("filename", "")

    safe_path = _safe_path_under("uploads", filename)
    if safe_path is None:
        return jsonify({"error": "Invalid path"}), 400

    try:
        with open(safe_path, "r") as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route("/download")
def download_file():
    """
    VULNERABILITY: Path Traversal with os.path.join misuse
    os.path.join doesn't prevent traversal when path starts with /
    """
    filename = request.args.get("file", "")

    base_dir = "/var/www/files"
    safe_path = _safe_path_under(base_dir, filename)
    if safe_path is None:
        return jsonify({"error": "Invalid path"}), 400

    try:
        with open(safe_path, "rb") as f:
            content = f.read()
        return Response(
            content,
            mimetype="application/octet-stream",
            headers={"X-Content-Type-Options": "nosniff"},
        )
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route("/deserialize", methods=["POST"])
def deserialize_data():
    """
    VULNERABILITY: Insecure Deserialization
    Pickle loads untrusted data from user input.
    """
    data = request.get_data()

    try:
        text = data.decode("utf-8")
        obj = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "Invalid JSON"}), 400

    return jsonify({"type": str(type(obj)), "value": str(obj)})


@app.route("/eval", methods=["POST"])
def evaluate_expression():
    """
    VULNERABILITY: Code Injection via eval
    User input is directly evaluated as Python code.
    """
    data = request.get_json()
    expression = data.get("expr", "")

    try:
        result = ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return jsonify({"error": "Invalid expression"}), 400

    return jsonify({"result": str(result)})


@app.route("/render")
def render_template_unsafe():
    """
    VULNERABILITY: Server-Side Template Injection
    User input is used in template string without sanitization.
    """
    name = request.args.get("name", "Guest")
    safe_name = html.escape(name, quote=True)

    template = f"<html><body><h1>Hello {safe_name}!</h1></body></html>"

    return template


def log_action(action, user_input):
    """
    VULNERABILITY: Log Injection
    User input is written directly to logs without sanitization.
    """
    log_message = f"Action: {action}, Input: {user_input}"

    with open("app.log", "a") as log_file:
        log_file.write(log_message + "\n")


@app.route("/ping", methods=["POST"])
def ping_host():
    """
    VULNERABILITY: Command Injection via subprocess
    Host parameter is passed directly to ping command.
    """
    data = request.get_json()
    host = data.get("host", "")

    if not host or not _PING_HOST_RE.fullmatch(host):
        return jsonify({"error": "Invalid host"}), 400

    output = subprocess.check_output(
        ["ping", "-c", "1", "--", host],
        text=True,
    )

    return jsonify({"output": output})


def init_db():
    """Initialize the database with sample data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO users (id, name, email, password)
        VALUES (1, 'Alice', 'alice@example.com', 'password123')
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    _debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=_debug, host="0.0.0.0", port=5000)
