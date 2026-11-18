import os, json, sqlite3, secrets, hashlib, hmac, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from contextlib import contextmanager

DB=os.getenv("DATABASE_PATH","motif-planner.sqlite3")
SECRET=os.getenv("MOTIF_SECRET_KEY","").encode()
INVITE=os.getenv("MOTIF_INVITE_CODE","")
FRONTEND=os.getenv("FRONTEND_ORIGIN","https://leonhexunxu-cmyk.github.io")
PORT=int(os.getenv("PORT","8787"))
def now(): return datetime.now(timezone.utc).isoformat()
@contextmanager
def db():
 c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row
 try:
  yield c
  c.commit()
 except Exception:
  c.rollback();raise
 finally:c.close()
def init():
 with db() as c:
  c.executescript("""
  PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,salt TEXT NOT NULL,department TEXT DEFAULT '',role TEXT DEFAULT 'member',status TEXT DEFAULT 'available',created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS invites(code_hash TEXT PRIMARY KEY,created_by INTEGER NOT NULL,used INTEGER DEFAULT 0,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,title TEXT NOT NULL,description TEXT DEFAULT '',assignee_id INTEGER,due_date TEXT DEFAULT '',priority TEXT DEFAULT 'normal',status TEXT DEFAULT 'todo',created_by INTEGER NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,title TEXT NOT NULL,starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,location TEXT DEFAULT '',kind TEXT DEFAULT 'Équipe',created_by INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY,created_by INTEGER NOT NULL,created_at TEXT NOT NULL,ended INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS signals(id INTEGER PRIMARY KEY,call_id TEXT NOT NULL,user_id INTEGER NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
  """)
def pw_hash(p,s): return hashlib.pbkdf2_hmac("sha256",p.encode(),s,240000).hex()
def token_hash(t): return hashlib.sha256(t.encode()).hexdigest()
def make_token(uid):
 t=secrets.token_urlsafe(36)
 with db() as c:c.execute("INSERT INTO sessions VALUES(?,?,?)",(token_hash(t),uid,int(time.time())+60*60*24*14))
 return t
def user_dict(r): return {k:r[k] for k in ("id","name","email","department","role","status")}
def body(h):
 n=int(h.headers.get("Content-Length","0"))
 if n>100000: raise ValueError("Payload trop volumineux")
 raw=h.rfile.read(n) if n else b"{}"
 x=json.loads(raw)
 if not isinstance(x,dict): raise ValueError("JSON objet attendu")
 return x
class Handler(BaseHTTPRequestHandler):
 server_version="MotifPlanner/1.0"
 def log_message(self,*a): print("%s - %s"%(self.address_string(),a[0]%a[1:]))
 def send(self,status,data):
  raw=json.dumps(data,ensure_ascii=False).encode()
  self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff");self.send_header("Access-Control-Allow-Origin",FRONTEND);self.send_header("Vary","Origin");self.send_header("Access-Control-Allow-Headers","Authorization, Content-Type");self.send_header("Access-Control-Allow-Methods","GET, POST, PATCH, DELETE, OPTIONS");self.end_headers();self.wfile.write(raw)
 def do_OPTIONS(self):
  self.send_response(204);self.send_header("Access-Control-Allow-Origin",FRONTEND);self.send_header("Access-Control-Allow-Headers","Authorization, Content-Type");self.send_header("Access-Control-Allow-Methods","GET, POST, PATCH, DELETE, OPTIONS");self.send_header("Access-Control-Max-Age","600");self.end_headers()
 def auth(self):
  v=self.headers.get("Authorization","")
  if not v.startswith("Bearer "):return None
  with db() as c:
   r=c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?",(token_hash(v[7:]),int(time.time()))).fetchone()
  return r
 def require(self):
  u=self.auth()
  if not u: self.send(401,{"detail":"Session invalide ou expirée"});return None
  return u
 def do_GET(self):
  try:
   p=urlparse(self.path);path=p.path
   if path=="/health":return self.send(200,{"ok":True,"service":"motif-planner"})
   u=self.require()
   if not u:return
   with db() as c:
    if path=="/api/auth/me":return self.send(200,{"user":user_dict(u)})
    if path=="/api/tasks":
     rows=c.execute("SELECT t.*,u.name assignee_name FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id ORDER BY CASE t.status WHEN 'done' THEN 2 ELSE 0 END,t.due_date").fetchall();return self.send(200,[dict(x) for x in rows])
    if path=="/api/events":return self.send(200,[dict(x) for x in c.execute("SELECT * FROM events ORDER BY starts_at").fetchall()])
    if path=="/api/members":return self.send(200,[user_dict(x) for x in c.execute("SELECT * FROM users ORDER BY name").fetchall()])
    if path=="/api/messages":
     after=int(parse_qs(p.query).get("after",["0"])[0]);return self.send(200,[dict(x) for x in c.execute("SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id>? ORDER BY m.id DESC LIMIT 150",(after,)).fetchall()][::-1])
    if path=="/api/rtc-config":
     ice=[{"urls":"stun:stun.l.google.com:19302"}]
     if os.getenv("TURN_URL") and os.getenv("TURN_USERNAME") and os.getenv("TURN_CREDENTIAL"):ice.append({"urls":os.environ["TURN_URL"],"username":os.environ["TURN_USERNAME"],"credential":os.environ["TURN_CREDENTIAL"]})
     return self.send(200,{"iceServers":ice})
    if path.startswith("/api/calls/") and path.endswith("/signals"):
     cid=path.split("/")[3];after=int(parse_qs(p.query).get("after",["0"])[0])
     if not c.execute("SELECT 1 FROM calls WHERE id=? AND ended=0",(cid,)).fetchone():return self.send(404,{"detail":"Appel introuvable"})
     rows=c.execute("SELECT * FROM signals WHERE call_id=? AND user_id<>? AND id>? ORDER BY id",(cid,u["id"],after)).fetchall()
     return self.send(200,[{"id":r["id"],"kind":r["kind"],"payload":json.loads(r["payload"])} for r in rows])
   return self.send(404,{"detail":"Route inconnue"})
  except Exception as e:return self.send(400,{"detail":str(e)})
 def do_POST(self):
  try:
   path=urlparse(self.path).path;b=body(self)
   if path=="/api/auth/register":
    name=str(b.get("name","")).strip();email=str(b.get("email","")).strip().lower();pw=str(b.get("password",""));code=str(b.get("invite",""))
    if len(name)<2 or len(email)>254 or "@" not in email or len(pw)<10:return self.send(400,{"detail":"Nom, email valide et mot de passe de 10 caractères minimum requis"})
    with db() as c:
     count=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
     if count==0:
      if not INVITE or not hmac.compare_digest(code,INVITE):return self.send(403,{"detail":"Code de première activation invalide"})
      role="admin"
     else:
      ch=hashlib.sha256(code.encode()).hexdigest()
      inv=c.execute("SELECT code_hash FROM invites WHERE code_hash=? AND used=0",(ch,)).fetchone()
      if not inv:return self.send(403,{"detail":"Invitation invalide ou déjà utilisée"})
      c.execute("UPDATE invites SET used=1 WHERE code_hash=?",(ch,));role="member"
     salt=secrets.token_bytes(16)
     try:c.execute("INSERT INTO users(name,email,password,salt,role,created_at) VALUES(?,?,?,?,?,?)",(name,email,pw_hash(pw,salt),salt.hex(),role,now()))
     except sqlite3.IntegrityError:return self.send(409,{"detail":"Cet email est déjà utilisé"})
     uid=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()[0]
    t=make_token(uid)
    with db() as c:r=c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    return self.send(201,{"token":t,"user":user_dict(r)})
   if path=="/api/auth/login":
    email=str(b.get("email","")).strip().lower();pw=str(b.get("password",""))
    with db() as c:r=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not r or not hmac.compare_digest(pw_hash(pw,bytes.fromhex(r["salt"])),r["password"]):return self.send(401,{"detail":"Identifiants incorrects"})
    return self.send(200,{"token":make_token(r["id"]),"user":user_dict(r)})
   u=self.require()
   if not u:return
   with db() as c:
    if path=="/api/auth/logout":
     c.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash(self.headers.get("Authorization","")[7:]),));return self.send(200,{"ok":True})
    if path=="/api/invites":
     if u["role"] not in ("admin","manager"):return self.send(403,{"detail":"Permission insuffisante"})
     code=str(b.get("code",""))
     if len(code)<12:return self.send(400,{"detail":"Code invalide"})
     c.execute("INSERT INTO invites(code_hash,created_by,created_at) VALUES(?,?,?)",(hashlib.sha256(code.encode()).hexdigest(),u["id"],now()));return self.send(201,{"ok":True})
    if path=="/api/tasks":
     title=str(b.get("title","")).strip()
     if not title:return self.send(400,{"detail":"Titre requis"})
     assignee=b.get("assignee_id") or None
     if assignee and u["role"]=="member" and int(assignee)!=u["id"]:return self.send(403,{"detail":"Vous ne pouvez assigner qu’à vous-même"})
     if u["role"]=="member" and assignee is None:assignee=u["id"]
     cur=c.execute("INSERT INTO tasks(title,description,assignee_id,due_date,priority,created_by,created_at) VALUES(?,?,?,?,?,?,?)",(title,str(b.get("description",""))[:5000],assignee,str(b.get("due_date",""))[:10],b.get("priority","normal"),u["id"],now()));return self.send(201,{"id":cur.lastrowid})
    if path=="/api/events":
     title=str(b.get("title","")).strip();start=str(b.get("starts_at",""));end=str(b.get("ends_at",""))
     if not title or not start or not end or end<=start:return self.send(400,{"detail":"Titre et dates cohérentes requis"})
     cur=c.execute("INSERT INTO events(title,starts_at,ends_at,location,kind,created_by) VALUES(?,?,?,?,?,?)",(title,start,end,str(b.get("location",""))[:200],str(b.get("kind","Équipe"))[:60],u["id"]));return self.send(201,{"id":cur.lastrowid})
    if path=="/api/messages":
     msg=str(b.get("body","")).strip()
     if not msg or len(msg)>4000:return self.send(400,{"detail":"Message vide ou trop long"})
     cur=c.execute("INSERT INTO messages(user_id,body,created_at) VALUES(?,?,?)",(u["id"],msg,now()));return self.send(201,{"id":cur.lastrowid})
    if path=="/api/calls":
     cid=secrets.token_urlsafe(16);c.execute("INSERT INTO calls(id,created_by,created_at) VALUES(?,?,?)",(cid,u["id"],now()));return self.send(201,{"id":cid})
    if path.startswith("/api/calls/") and path.endswith("/signals"):
     cid=path.split("/")[3]
     if not c.execute("SELECT 1 FROM calls WHERE id=? AND ended=0",(cid,)).fetchone():return self.send(404,{"detail":"Appel introuvable"})
     kind=str(b.get("kind",""));payload=b.get("payload")
     if kind not in ("offer","answer","candidate") or payload is None:return self.send(400,{"detail":"Signal invalide"})
     c.execute("INSERT INTO signals(call_id,user_id,kind,payload,created_at) VALUES(?,?,?,?,?)",(cid,u["id"],kind,json.dumps(payload),now()));return self.send(201,{"ok":True})
   return self.send(404,{"detail":"Route inconnue"})
  except Exception as e:return self.send(400,{"detail":str(e)})
 def do_PATCH(self):
  try:
   u=self.require()
   if not u:return
   path=urlparse(self.path).path
   if not path.startswith("/api/tasks/"):return self.send(404,{"detail":"Route inconnue"})
   tid=int(path.rsplit("/",1)[1]);b=body(self)
   with db() as c:
    t=c.execute("SELECT * FROM tasks WHERE id=?",(tid,)).fetchone()
    if not t:return self.send(404,{"detail":"Tâche introuvable"})
    if u["role"]=="member" and t["assignee_id"]!=u["id"]:return self.send(403,{"detail":"Tâche non assignée à votre compte"})
    allowed={"status","assignee_id","due_date","priority","title","description"}
    changes={k:v for k,v in b.items() if k in allowed}
    if u["role"]=="member":changes={k:v for k,v in changes.items() if k=="status"}
    if not changes:return self.send(400,{"detail":"Aucun champ modifiable"})
    c.execute("UPDATE tasks SET "+",".join(k+"=?" for k in changes)+" WHERE id=?",(*changes.values(),tid))
    return self.send(200,{"ok":True})
  except Exception as e:return self.send(400,{"detail":str(e)})
if __name__=="__main__":
 if not SECRET: print("WARNING: set MOTIF_SECRET_KEY before production")
 init();print("Motif Planner API listening on",PORT);ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
