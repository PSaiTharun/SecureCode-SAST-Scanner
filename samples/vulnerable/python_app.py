# Deliberately vulnerable training fixture; never deploy.
import os
api_key = "DEMO_ONLY_REPLACE_ME_12345"
def get_user(cursor, user_id): cursor.execute("SELECT * FROM users WHERE id = " + user_id)
def run_report(name): os.system("cat " + name)
def render(request): return "<h1>" + request.args.get("name") + "</h1>"
def calculate(code): return eval(code)
def download(root, name): return open(root + "/" + name).read()
