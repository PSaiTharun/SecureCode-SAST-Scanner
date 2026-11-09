# Safer equivalents of samples/vulnerable/flask_app.py.
import html
import json
import shlex
import subprocess
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"example.com", "example.org"}


@app.route("/user")
def user():
    uid = int(request.args.get("id", "0"))
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return "<h1>Hello " + html.escape(request.args.get("name", "")) + "</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        abort(400)
    subprocess.run(["ping", "-c1", host], check=True)
    subprocess.run("ls " + shlex.quote(request.form["d"]), shell=True)
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    return str(json.loads(request.data))
