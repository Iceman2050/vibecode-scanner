"""VULNERABLE fixture — every line below is intentionally bad.
Fires VC-001, VC-002, VC-003, VC-004, VC-005, VC-006, VC-007, VC-008, VC-010.
"""
import os
import pickle
import random
import string

import requests
from flask import Flask, request

app = Flask(__name__)

# VC-001 — hardcoded secrets (the kind AI assistants paste into scaffolds)
API_KEY = "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
password = "hunter2"


# VC-007 — route with no auth check anywhere nearby
@app.route("/admin/delete")
def admin_delete():
    user_id = request.args.get("id")
    # VC-002 — SQL built with an f-string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    db.execute(query)
    # VC-003 — eval on request input
    result = eval(request.args.get("expr", "1+1"))
    return str(result)


@app.route("/load")
def load_blob():
    raw = request.get_data()
    # VC-004 — unpickling request bytes
    obj = pickle.loads(raw)
    return "ok"


@app.route("/ls")
def list_dir():
    user_dir = request.args.get("dir", "")
    # VC-005 — os.system with concatenation
    os.system("ls " + user_dir)
    return "ok"


def make_reset_token():
    chars = string.ascii_letters + string.digits
    # VC-006 — token from the non-crypto random module
    token = "".join(random.choice(chars) for _ in range(32))
    return token


@app.route("/fetch")
def fetch_profile():
    user_id = request.args.get("uid", "")
    # VC-010 — server-side fetch of a user-built URL
    r = requests.get(f"https://internal/api/users/{user_id}")
    return r.text


@app.route("/read")
def read_file():
    filename = request.args.get("f", "")
    # VC-008 — file opened with a concatenated path
    with open("/var/data/" + filename) as fh:
        return fh.read()
