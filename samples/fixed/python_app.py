# Illustrative safer patterns; adapt to your framework.
import subprocess,os,json
from pathlib import Path
def get_user(cursor,user_id): cursor.execute("SELECT * FROM users WHERE id = ?",(user_id,))
def run_report(name):
 if name not in {'daily.csv','monthly.csv'}: raise ValueError('invalid report')
 subprocess.run(['cat',name],check=True)
def render(request): return {'name':request.args.get('name','')} # use autoescaped template

def calculate(data): return json.loads(data)
def download(root,name):
 base=Path(root).resolve(); candidate=(base/name).resolve()
 if base not in candidate.parents: raise ValueError('path escape')
 return candidate.read_text()
def secret(): return os.environ['SERVICE_API_KEY']
