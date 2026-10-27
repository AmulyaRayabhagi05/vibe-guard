# Test fixture for rules/app/python.yaml (ruleid lines must match, ok lines must not).
import hashlib
import os
import pickle
import subprocess

import jwt
import requests
import yaml
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask import Flask, redirect, request, send_file

app = FastAPI()
web = Flask(__name__)


def find(cursor, user_id, name):
    # ruleid: vc-app-py-sql-injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: vc-app-py-sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ok: vc-app-py-sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def convert(filename):
    # ruleid: vc-app-py-command-injection
    subprocess.run(f"convert {filename} out.png", shell=True)
    # ruleid: vc-app-py-command-injection
    os.system("rm -rf " + filename)
    # ok: vc-app-py-command-injection
    subprocess.run(["convert", filename, "out.png"])


# ruleid: vc-app-py-eval
result = eval(request.args["expr"])

# ruleid: vc-app-py-debug-on
web.run(host="0.0.0.0", debug=True)

# ruleid: vc-app-py-hardcoded-secret-key
web.secret_key = "dev-secret-123"
# ok: vc-app-py-hardcoded-secret-key
web.secret_key = os.environ["SECRET_KEY"]

# ruleid: vc-app-py-jwt-no-verify
claims = jwt.decode(token, options={"verify_signature": False})

# ruleid: vc-app-py-cors-wildcard-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])


# ruleid: vc-app-py-fastapi-idor
@app.get("/api/notes/{note_id}")
async def get_note(note_id: int):
    return db.get(Note, note_id)


# ok: vc-app-py-fastapi-idor
@app.get("/api/orders/{order_id}")
async def get_order(order_id: int, user=Depends(get_current_user)):
    return db.query(Order).filter_by(id=order_id, owner_id=user.id).first()


# ruleid: vc-app-py-flask-idor
@web.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    return render_template("invoice.html", invoice=Invoice.query.get(invoice_id))


@web.route("/download")
def download():
    # ruleid: vc-app-py-path-traversal
    return send_file(os.path.join("uploads", request.args["name"]))


def preview():
    # ruleid: vc-app-py-ssrf
    return requests.get(request.args.get("url")).text


def go():
    # ruleid: vc-app-py-open-redirect
    return redirect(request.args.get("next"))


# ruleid: vc-app-py-unsafe-deserialization
data = pickle.loads(blob)
# ruleid: vc-app-py-unsafe-deserialization
cfg = yaml.load(text)
# ok: vc-app-py-unsafe-deserialization
cfg = yaml.safe_load(text)

# ruleid: vc-app-py-weak-password-hash
digest = hashlib.md5(password.encode()).hexdigest()
# ok: vc-app-py-weak-password-hash
etag = hashlib.md5(body).hexdigest()

# ruleid: vc-app-py-tls-verify-off
requests.get("https://internal.api", verify=False)
