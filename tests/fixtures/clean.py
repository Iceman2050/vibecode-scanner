"""CLEAN fixture — secure patterns only. Must produce zero findings."""
import os
import secrets
import sqlite3
import subprocess
from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)

DB = sqlite3.connect("app.db")

API_KEY = os.environ.get("API_KEY")  # from the environment, never hardcoded


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@app.route("/users")
@login_required
def list_users():
    uid = request.args.get("uid", "")
    # parameterized — no interpolation, no concatenation
    cur = DB.execute("SELECT id, name FROM users WHERE id = %s", (uid,))
    return jsonify(cur.fetchall())


@app.route("/run")
@login_required
def run_tool():
    name = request.args.get("name", "")
    # argument list, shell explicitly off
    subprocess.run(["/usr/bin/file", name], shell=False, check=True)
    return "ok"


def make_reset_token():
    # CSPRNG, not random.*
    return secrets.token_hex(32)


@app.route("/download")
@login_required
def download():
    filename = request.args.get("f", "")
    safe = os.path.basename(filename)
    base = "/var/data"
    path = os.path.join(base, safe)
    # containment check — stays inside the base directory
    if os.path.commonpath([base, os.path.abspath(path)]) != base:
        return jsonify({"error": "bad path"}), 400
    with open(path, "rb") as fh:
        return fh.read()
