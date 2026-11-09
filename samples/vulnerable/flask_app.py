# Deliberately vulnerable training fixture; never deploy.
import os
import pickle
import subprocess
import requests
from flask import Flask, redirect, request

app = Flask(__name__)


def run_ping(host):
    os.system("ping -c1 " + host)              # reached by tainted data via the route below


@app.route("/user")
def user():
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + uid
    cursor.execute(query)                       # SQL injection (multi-step flow)
    return "<h1>Hello " + request.args["name"] + "</h1>"   # reflected XSS


@app.route("/ping")
def ping():
    run_ping(request.args["host"])              # interprocedural command injection
    subprocess.run("ls " + request.form["d"], shell=True)
    return "ok"


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text          # SSRF


@app.route("/go")
def go():
    return redirect(request.args.get("next"))              # open redirect


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                 # insecure deserialization


if __name__ == "__main__":
    app.run(debug=True)
