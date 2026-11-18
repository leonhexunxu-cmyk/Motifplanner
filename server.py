import os, json, sqlite3, secrets, hashlib, hmac, time, mimetypes, base64, urllib.request, urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from contextlib import contextmanager
from cryptography.fernet import Fernet

DB=os.getenv("DATABASE_PATH","motif-planner.sqlite3")
SECRET=os.getenv("MOTIF_SECRET_KEY","").encode()
INVITE=os.getenv("MOTIF_INVITE_CODE","")
FRONTEND=os.getenv("FRONTEND_ORIGIN","https://leonhexunxu-cmyk.github.io")
PORT=int(os.getenv("PORT","8787"))
def now(): return datetime.now(timezone.utc).isoformat()
def vault():
 if not SECRET: raise RuntimeError('MOTIF_SECRET_KEY doit être configurée')
 return Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET).digest()))
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
  CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT DEFAULT '',created_by INTEGER NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,title TEXT NOT NULL,description TEXT DEFAULT '',assignee_id INTEGER,due_date TEXT DEFAULT '',priority TEXT DEFAULT 'normal',status TEXT DEFAULT 'todo',created_by INTEGER NOT NULL,created_at TEXT NOT NULL,project_id INTEGER);
  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,title TEXT NOT NULL,starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,location TEXT DEFAULT '',kind TEXT DEFAULT 'Équipe',created_by INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY,created_by INTEGER NOT NULL,created_at TEXT NOT NULL,ended INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS signals(id INTEGER PRIMARY KEY,call_id TEXT NOT NULL,user_id INTEGER NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,title TEXT NOT NULL,body TEXT DEFAULT '',kind TEXT DEFAULT 'info',created_at TEXT NOT NULL,read_at TEXT DEFAULT '');
  CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,name TEXT NOT NULL,mime TEXT NOT NULL,size INTEGER NOT NULL,path TEXT NOT NULL,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT NOT NULL);
  """)
  user_cols={r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
  if "permissions" not in user_cols:c.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT ''")
  task_cols={r[1] for r in c.execute("PRAGMA table_info(tasks)").fetchall()}
  if "project_id" not in task_cols:c.execute("ALTER TABLE tasks ADD COLUMN project_id INTEGER")
  c.execute("UPDATE users SET department='Direction' WHERE role='admin' AND (department IS NULL OR department='')")
def pw_hash(p,s): return hashlib.pbkdf2_hmac("sha256",p.encode(),s,240000).hex()
def token_hash(t): return hashlib.sha256(t.encode()).hexdigest()
def make_token(uid):
 t=secrets.token_urlsafe(36)
 with db() as c:c.execute("INSERT INTO sessions VALUES(?,?,?)",(token_hash(t),uid,int(time.time())+60*60*24*14))
 return t
PERM_KEYS=("create_tasks","assign_tasks","manage_projects","manage_calendar","share_files","use_ai","use_messages","use_calls")
def default_permissions(role):
 return {k:(role=="admin" or k in ("create_tasks","use_ai","share_files","use_messages","use_calls")) for k in PERM_KEYS}
def has_perm(u,key):
 if u["role"]=="admin":return True
 try: saved=json.loads(u["permissions"] or "{}")
 except Exception: saved={}
 return bool(saved.get(key,default_permissions(u["role"]).get(key,False)))
def user_dict(r):
 try: saved=json.loads(r["permissions"] or "{}")
 except Exception: saved={}
 defaults=default_permissions(r["role"])
 return {**{k:r[k] for k in ("id","name","email","role","status")},"department":r["department"] or ("Direction" if r["role"]=="admin" else ""),"permissions":{k:saved.get(k,defaults[k]) for k in PERM_KEYS}}
def body(h):
 n=int(h.headers.get("Content-Length","0"))
 if n>7500000: raise ValueError("Payload trop volumineux (maximum 5 Mo pour un fichier)")
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
   static_files={"/":"index.html","/index.html":"index.html","/styles.css":"styles.css","/app.js":"app.js","/config.js":"config.js"}
   if path in static_files:
    file=Path(__file__).parent/static_files[path]
    if not file.is_file():return self.send(404,{"detail":"Fichier introuvable"})
    raw=file.read_bytes();self.send_response(200);self.send_header("Content-Type",mimetypes.guess_type(str(file))[0] or "application/octet-stream");self.send_header("Content-Length",str(len(raw)));self.send_header("Cache-Control","no-cache");self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(raw);return
   u=self.require()
   if not u:return
   if path=="/api/messages" and not has_perm(u,"use_messages"):return self.send(403,{"detail":"Accès à la messagerie non autorisé"})
   if (path=="/api/files" or path.startswith("/api/files/")) and not has_perm(u,"share_files"):return self.send(403,{"detail":"Accès aux fichiers non autorisé"})
   if (path=="/api/rtc-config" or path.startswith("/api/calls/")) and not has_perm(u,"use_calls"):return self.send(403,{"detail":"Accès aux appels non autorisé"})
   with db() as c:
    if path=="/api/auth/me":return self.send(200,{"user":user_dict(u)})
    if path=="/api/tasks":
     rows=c.execute("SELECT t.*,u.name assignee_name,p.name project_name FROM tasks t LEFT JOIN users u ON u.id=t.assignee_id LEFT JOIN projects p ON p.id=t.project_id ORDER BY CASE t.status WHEN 'done' THEN 2 ELSE 0 END,t.due_date").fetchall();return self.send(200,[dict(x) for x in rows])
    if path=="/api/projects":return self.send(200,[dict(x) for x in c.execute("SELECT * FROM projects ORDER BY name").fetchall()])
    if path=="/api/events":return self.send(200,[dict(x) for x in c.execute("SELECT * FROM events ORDER BY starts_at").fetchall()])
    if path=="/api/members":return self.send(200,[user_dict(x) for x in c.execute("SELECT * FROM users ORDER BY name").fetchall()])
    if path=="/api/notifications":return self.send(200,[dict(x) for x in c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(u["id"],)).fetchall()])
    if path=="/api/files":return self.send(200,[{k:r[k] for k in ("id","name","mime","size","created_at","user_id")} for r in c.execute("SELECT * FROM files ORDER BY id DESC LIMIT 100").fetchall()])
    if path=="/api/ai/status":
     row=c.execute("SELECT value FROM settings WHERE key='openrouter_key'").fetchone()
     return self.send(200,{"configured":bool(row),"provider":"OpenRouter"})
    if path.startswith("/api/files/") and path.endswith("/download"):
     fid=int(path.split("/")[3]);r=c.execute("SELECT * FROM files WHERE id=?",(fid,)).fetchone()
     if not r:return self.send(404,{"detail":"Fichier introuvable"})
     f=Path(r["path"])
     if not f.is_file():return self.send(404,{"detail":"Fichier indisponible"})
     raw=f.read_bytes();self.send_response(200);self.send_header("Content-Type",r["mime"]);self.send_header("Content-Length",str(len(raw)));self.send_header("Content-Disposition","attachment; filename="+r["name"].replace('"',''));self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(raw);return
    if path=="/api/messages":
     after=int(parse_qs(p.query).get("after",["0"])[0]);return self.send(200,[dict(x) for x in c.execute("SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.user_id WHERE m.id>? ORDER BY m.id DESC LIMIT 150",(after,)).fetchall()][::-1])
    if path=="/api/rtc-config":
     ice=[{"urls":"stun:stun.l.google.com:19302"}]
     if os.getenv("TURN_URL") and os.getenv("TURN_USERNAME") and os.getenv("TURN_CREDENTIAL"):ice.append({"urls":os.environ["TURN_URL"],"username":os.environ["TURN_USERNAME"],"credential":os.environ["TURN_CREDENTIAL"]})
     return self.send(200,{"iceServers":ice})
    if path.startswith("/api/calls/") and path.endswith("/signals"):
     if not has_perm(u,"use_calls"):return self.send(403,{"detail":"Droit d’appel requis"})
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
    if len(name)<2 or len(email)>254 or "@" not in email or len(pw)<10 or len(pw)>128:return self.send(400,{"detail":"Nom, email valide et mot de passe de 10 caractères minimum requis"})
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
     department="Direction" if role=="admin" else "À définir"
     try:c.execute("INSERT INTO users(name,email,password,salt,department,role,created_at) VALUES(?,?,?,?,?,?,?)",(name,email,pw_hash(pw,salt),salt.hex(),department,role,now()))
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
    if path=="/api/admin/users":
     if u["role"]!="admin":return self.send(403,{"detail":"Réservé à l’administrateur"})
     name=str(b.get("name","")).strip()
     email=str(b.get("email","")).strip().lower()
     pw=str(b.get("password",""))
     department=str(b.get("department","")).strip()[:80]
     role=str(b.get("role","member"))
     if len(name)<2 or len(email)>254 or "@" not in email or len(pw)<10 or len(pw)>128:
      return self.send(400,{"detail":"Nom, email valide et mot de passe de 10 caractères minimum requis"})
     if not department:return self.send(400,{"detail":"Département requis"})
     if role not in ("admin","manager","member"):return self.send(400,{"detail":"Rôle invalide"})
     salt=secrets.token_bytes(16)
     try:
      cur=c.execute("INSERT INTO users(name,email,password,salt,department,role,created_at) VALUES(?,?,?,?,?,?,?)",(name,email,pw_hash(pw,salt),salt.hex(),department,role,now()))
     except sqlite3.IntegrityError:return self.send(409,{"detail":"Cet email est déjà utilisé"})
     created=c.execute("SELECT * FROM users WHERE id=?",(cur.lastrowid,)).fetchone()
     return self.send(201,{"user":user_dict(created)})
    if path=="/api/invites":
     if u["role"] not in ("admin","manager"):return self.send(403,{"detail":"Permission insuffisante"})
     code=str(b.get("code",""))
     if len(code)<12:return self.send(400,{"detail":"Code invalide"})
     c.execute("INSERT INTO invites(code_hash,created_by,created_at) VALUES(?,?,?)",(hashlib.sha256(code.encode()).hexdigest(),u["id"],now()));return self.send(201,{"ok":True})
    if path=="/api/projects":
     if not has_perm(u,"manage_projects"):return self.send(403,{"detail":"Droit de gestion des projets requis"})
     name=str(b.get("name","")).strip()
     if not name:return self.send(400,{"detail":"Nom de projet requis"})
     try:cur=c.execute("INSERT INTO projects(name,description,created_by,created_at) VALUES(?,?,?,?)",(name[:80],str(b.get("description",""))[:500],u["id"],now()))
     except sqlite3.IntegrityError:return self.send(409,{"detail":"Ce projet existe déjà"})
     return self.send(201,{"id":cur.lastrowid})
    if path=="/api/account/profile":
     department=str(b.get("department","")).strip()[:80]
     if not department:return self.send(400,{"detail":"Un département est obligatoire"})
     c.execute("UPDATE users SET department=? WHERE id=?",(department,u["id"]))
     return self.send(200,{"user":user_dict(c.execute("SELECT * FROM users WHERE id=?",(u["id"],)).fetchone())})
    if path=="/api/tasks":
     if not has_perm(u,"create_tasks"):return self.send(403,{"detail":"Droit de création de tâches requis"})
     title=str(b.get("title","")).strip()
     if not title:return self.send(400,{"detail":"Titre requis"})
     due=str(b.get("due_date",""))[:10]
     try:datetime.strptime(due,"%Y-%m-%d")
     except Exception:return self.send(400,{"detail":"Une date valide est obligatoire pour planifier la tâche"})
     assignee=b.get("assignee_id") or None
     if assignee and int(assignee)!=u["id"] and not has_perm(u,"assign_tasks"):return self.send(403,{"detail":"Droit d’assignation requis"})
     if u["role"]=="member" and assignee is None:assignee=u["id"]
     project_id=b.get("project_id") or None
     if project_id and not c.execute("SELECT 1 FROM projects WHERE id=?",(int(project_id),)).fetchone():return self.send(400,{"detail":"Projet introuvable"})
     cur=c.execute("INSERT INTO tasks(title,description,assignee_id,due_date,priority,created_by,created_at,project_id) VALUES(?,?,?,?,?,?,?,?)",(title,str(b.get("description",""))[:5000],assignee,due,b.get("priority","normal"),u["id"],now(),project_id))
     if assignee and int(assignee)!=u["id"]:c.execute("INSERT INTO notifications(user_id,title,body,kind,created_at) VALUES(?,?,?,?,?)",(int(assignee),"Nouvelle tâche",title,"task",now()))
     return self.send(201,{"id":cur.lastrowid})
    if path=="/api/events":
     if not has_perm(u,"manage_calendar"):return self.send(403,{"detail":"Droit de gestion du calendrier requis"})
     title=str(b.get("title","")).strip();start=str(b.get("starts_at",""));end=str(b.get("ends_at",""))
     if not title or not start or not end or end<=start:return self.send(400,{"detail":"Titre et dates cohérentes requis"})
     cur=c.execute("INSERT INTO events(title,starts_at,ends_at,location,kind,created_by) VALUES(?,?,?,?,?,?)",(title,start,end,str(b.get("location",""))[:200],str(b.get("kind","Équipe"))[:60],u["id"]));return self.send(201,{"id":cur.lastrowid})
    if path=="/api/messages":
     if not has_perm(u,"use_messages"):return self.send(403,{"detail":"Accès à la messagerie non autorisé"})
     msg=str(b.get("body","")).strip()
     if not msg or len(msg)>4000:return self.send(400,{"detail":"Message vide ou trop long"})
     cur=c.execute("INSERT INTO messages(user_id,body,created_at) VALUES(?,?,?)",(u["id"],msg,now()))
     for member in c.execute("SELECT id FROM users WHERE id<>?",(u["id"],)).fetchall():
      c.execute("INSERT INTO notifications(user_id,title,body,kind,created_at) VALUES(?,?,?,?,?)",(member["id"],"Nouveau message",u["name"]+": "+msg[:160],"message",now()))
     return self.send(201,{"id":cur.lastrowid})
    if path=="/api/files":
     if not has_perm(u,"share_files"):return self.send(403,{"detail":"Droit de partage de fichiers requis"})
     name=Path(str(b.get("name","fichier"))).name[:180]
     mime=str(b.get("mime","application/octet-stream")).lower()[:100]
     allowed=("image/png","image/jpeg","image/gif","image/webp","application/pdf","text/plain","application/zip")
     if mime not in allowed:return self.send(400,{"detail":"Type de fichier non autorisé"})
     try: raw=base64.b64decode(str(b.get("data","")),validate=True)
     except Exception:return self.send(400,{"detail":"Fichier illisible"})
     if not raw or len(raw)>5*1024*1024:return self.send(400,{"detail":"Fichier vide ou supérieur à 5 Mo"})
     folder=Path("uploads");folder.mkdir(exist_ok=True);dest=folder/secrets.token_hex(16);dest.write_bytes(raw)
     cur=c.execute("INSERT INTO files(user_id,name,mime,size,path,created_at) VALUES(?,?,?,?,?,?)",(u["id"],name,mime,len(raw),str(dest),now()))
     for member in c.execute("SELECT id FROM users WHERE id<>?",(u["id"],)).fetchall():
      c.execute("INSERT INTO notifications(user_id,title,body,kind,created_at) VALUES(?,?,?,?,?)",(member["id"],"Fichier partagé",u["name"]+" a partagé "+name,"file",now()))
     return self.send(201,{"id":cur.lastrowid})
    if path=="/api/notifications/read":
     c.execute("UPDATE notifications SET read_at=? WHERE id=? AND user_id=?",(now(),int(b.get("id",0)),u["id"]))
     return self.send(200,{"ok":True})
    if path=="/api/settings/ai-key":
     if u["role"]!="admin":return self.send(403,{"detail":"Réservé à l’administrateur"})
     key=str(b.get("key","")).strip()
     if not key.startswith("sk-or-") or len(key)>500:return self.send(400,{"detail":"Clé OpenRouter invalide"})
     enc=vault().encrypt(key.encode()).decode()
     c.execute("INSERT INTO settings(key,value,updated_at) VALUES('openrouter_key',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(enc,now()))
     return self.send(200,{"ok":True,"configured":True})
    if path=="/api/ai/chat":
     if not has_perm(u,"use_ai"):return self.send(403,{"detail":"Accès à l’assistant IA non autorisé"})
     row=c.execute("SELECT value FROM settings WHERE key='openrouter_key'").fetchone()
     if not row:return self.send(400,{"detail":"Clé OpenRouter non configurée par l’administrateur"})
     prompt=str(b.get("message","")).strip()
     if not prompt or len(prompt)>6000:return self.send(400,{"detail":"Message vide ou trop long"})
     key=vault().decrypt(row["value"].encode()).decode()
     tools_spec=[{"type":"function","function":{"name":"create_task","description":"Créer une tâche Motif Planner et l’ajouter au planning uniquement si l’utilisateur le demande explicitement et donne une date d’échéance claire.","parameters":{"type":"object","properties":{"title":{"type":"string"},"description":{"type":"string"},"due_date":{"type":"string","description":"Date ISO YYYY-MM-DD"},"priority":{"type":"string","enum":["low","normal","high"]},"project_id":{"type":"integer"},"assignee_id":{"type":"integer"}},"required":["title","due_date"]}}}]
     payload=json.dumps({"model":"baidu/ernie-5.5-flash-preview:free","messages":[{"role":"system","content":"Tu es l’assistant de travail de Motif AI. Réponds en français, clairement et professionnellement. Tu peux créer une tâche uniquement si l’utilisateur le demande explicitement. Pour cela, appelle create_task et exige un titre et une date précise. Ne prétends jamais avoir créé une tâche sans appel d’outil réussi. Les projets disponibles sont : "+", ".join(r["name"]+" (id "+str(r["id"])+")" for r in c.execute("SELECT id,name FROM projects").fetchall())},{"role":"user","content":prompt}],"tools":tools_spec,"tool_choice":"auto","max_tokens":1200}).encode()
     req=urllib.request.Request("https://openrouter.ai/api/v1/chat/completions",data=payload,headers={"Authorization":"Bearer "+key,"Content-Type":"application/json","HTTP-Referer":"https://motifplanner-api-7p28.onrender.com","X-Title":"Motif Planner"},method="POST")
     try:
      with urllib.request.urlopen(req,timeout=45) as response: result=json.loads(response.read())
      msg=result["choices"][0]["message"];created=None
      for call in msg.get("tool_calls",[]):
       if call.get("function",{}).get("name")!="create_task":continue
       args=json.loads(call["function"].get("arguments","{}"))
       if not has_perm(u,"create_tasks"):return self.send(403,{"detail":"Droit de création de tâches requis"})
       title=str(args.get("title","")).strip()[:180];due=str(args.get("due_date",""))[:10]
       try:datetime.strptime(due,"%Y-%m-%d")
       except Exception:return self.send(400,{"detail":"Le titre et une date valide sont requis pour créer la tâche"})
       if not title:return self.send(400,{"detail":"Titre requis"})
       assignee=args.get("assignee_id") or None
       if assignee and int(assignee)!=u["id"] and not has_perm(u,"assign_tasks"):return self.send(403,{"detail":"Droit d’assignation requis"})
       if u["role"]=="member" and assignee is None:assignee=u["id"]
       project_id=args.get("project_id") or None
       if project_id and not c.execute("SELECT 1 FROM projects WHERE id=?",(int(project_id),)).fetchone():project_id=None
       cur=c.execute("INSERT INTO tasks(title,description,assignee_id,due_date,priority,created_by,created_at,project_id) VALUES(?,?,?,?,?,?,?,?)",(title,str(args.get("description",""))[:5000],assignee,due,args.get("priority","normal"),u["id"],now(),project_id))
       created={"id":cur.lastrowid,"title":title,"due_date":due}
       if assignee and int(assignee)!=u["id"]:c.execute("INSERT INTO notifications(user_id,title,body,kind,created_at) VALUES(?,?,?,?,?)",(int(assignee),"Nouvelle tâche",title,"task",now()))
      answer=msg.get("content") or ("Tâche créée et ajoutée au planning." if created else "Je n’ai pas pu générer de réponse.")
      return self.send(200,{"answer":answer,"created_task":created})
     except urllib.error.HTTPError as err:return self.send(502,{"detail":"OpenRouter a refusé la requête (HTTP "+str(err.code)+")"})
     except Exception:return self.send(502,{"detail":"Impossible de contacter OpenRouter ou de traiter la réponse"})
    if path=="/api/calls":
     if not has_perm(u,"use_calls"):return self.send(403,{"detail":"Droit d’appel requis"})
     cid=secrets.token_urlsafe(16);c.execute("INSERT INTO calls(id,created_by,created_at) VALUES(?,?,?)",(cid,u["id"],now()));return self.send(201,{"id":cid})
    if path.startswith("/api/calls/") and path.endswith("/end"):
     cid=path.split("/")[3]
     c.execute("UPDATE calls SET ended=1 WHERE id=? AND created_by=?",(cid,u["id"]));return self.send(200,{"ok":True})
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
   if path.startswith("/api/admin/users/"):
    if u["role"]!="admin":return self.send(403,{"detail":"Réservé à l’administrateur"})
    uid=int(path.rsplit("/",1)[1]);b=body(self)
    with db() as c:
     target=c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
     if not target:return self.send(404,{"detail":"Membre introuvable"})
     if target["role"]=="admin":return self.send(403,{"detail":"Les droits d’un autre administrateur ne peuvent pas être modifiés ici"})
     department=str(b.get("department",target["department"])).strip()[:80]
     if not department:return self.send(400,{"detail":"Département requis"})
     permissions=b.get("permissions",{})
     if not isinstance(permissions,dict) or any(k not in PERM_KEYS for k in permissions):return self.send(400,{"detail":"Permissions invalides"})
     normalized={k:bool(permissions.get(k,default_permissions(target["role"])[k])) for k in PERM_KEYS}
     c.execute("UPDATE users SET department=?,permissions=? WHERE id=?",(department,json.dumps(normalized),uid))
     return self.send(200,{"user":user_dict(c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone())})
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
    if "status" in changes and changes["status"] not in ("todo","doing","done"):return self.send(400,{"detail":"Statut invalide"})
    if "priority" in changes and changes["priority"] not in ("low","normal","high"):return self.send(400,{"detail":"Priorité invalide"})
    if "assignee_id" in changes and not has_perm(u,"assign_tasks"):return self.send(403,{"detail":"Droit d’assignation requis"})
    if "due_date" in changes:
     try:datetime.strptime(str(changes["due_date"]),"%Y-%m-%d")
     except Exception:return self.send(400,{"detail":"Date invalide"})
    if "project_id" in b:changes["project_id"]=b.get("project_id") or None
    c.execute("UPDATE tasks SET "+",".join(k+"=?" for k in changes)+" WHERE id=?",(*changes.values(),tid))
    return self.send(200,{"ok":True})
  except Exception as e:return self.send(400,{"detail":str(e)})
if __name__=="__main__":
 if not SECRET: print("WARNING: set MOTIF_SECRET_KEY before production")
 init();print("Motif Planner API listening on",PORT);ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
