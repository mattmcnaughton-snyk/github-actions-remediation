"""
Vulnerable Flask Application - For SAST Demonstration

This application contains intentional security vulnerabilities for testing
automated security remediation with Snyk and Cursor CLI.

WARNING: DO NOT use this code in production!
"""

import os
import pickle
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULNERABILITY: Hardcoded secrets
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-proj-1234567890abcdefghijklmnop"
SECRET_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


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
    
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
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
    
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)
    
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
    
    os.system(f"cat {filename}")
    
    return jsonify({"status": "executed"})


@app.route("/process", methods=["POST"])
def process_file():
    """
    VULNERABILITY: Command Injection via subprocess with shell=True
    User input is passed to subprocess with shell enabled.
    """
    data = request.get_json()
    file_path = data.get("path", "")
    
    result = subprocess.run(
        f"wc -l {file_path}",
        shell=True,
        capture_output=True,
        text=True
    )
    
    return jsonify({"output": result.stdout})


@app.route("/read-file")
def read_file():
    """
    VULNERABILITY: Path Traversal
    User can escape the uploads directory using ../
    """
    filename = request.args.get("filename", "")
    
    file_path = f"uploads/{filename}"
    
    try:
        with open(file_path, "r") as f:
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
    file_path = os.path.join(base_dir, filename)
    
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route("/deserialize", methods=["POST"])
def deserialize_data():
    """
    VULNERABILITY: Insecure Deserialization
    Pickle loads untrusted data from user input.
    """
    data = request.get_data()
    
    obj = pickle.loads(data)
    
    return jsonify({"type": str(type(obj)), "value": str(obj)})


@app.route("/eval", methods=["POST"])
def evaluate_expression():
    """
    VULNERABILITY: Code Injection via eval
    User input is directly evaluated as Python code.
    """
    data = request.get_json()
    expression = data.get("expr", "")
    
    result = eval(expression)
    
    return jsonify({"result": str(result)})


@app.route("/render")
def render_template_unsafe():
    """
    VULNERABILITY: Server-Side Template Injection
    User input is used in template string without sanitization.
    """
    name = request.args.get("name", "Guest")
    
    template = f"<html><body><h1>Hello {name}!</h1></body></html>"
    
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
    
    output = subprocess.check_output(
        f"ping -c 1 {host}",
        shell=True,
        text=True
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
    app.run(debug=True, host="0.0.0.0", port=5000)
