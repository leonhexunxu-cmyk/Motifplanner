#!/usr/bin/env python3
"""Motif Planner API — stdlib only. Local/dev backend; bind to localhost by default."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import json, os, sqlite3, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get("MOTIF_DB", ROOT / "motif-planner.sqlite3"))
HOST = os.environ.get("MOTIF_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8787"))
ALLOWED_ORIGIN = os.environ.get("MOTIF_ORIGIN", "*")

def connect():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL,
        created_at REAL NOT NULL, updated_at REAL NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS presence (
        member_id TEXT PRIMARY KEY, payload TEXT NOT NULL, seen_at REAL NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS calls (
        id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at REAL NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS ice (
        id TEXT PRIMARY KEY, call_id TEXT NOT NULL, sender TEXT NOT NULL,
        payload TEXT NOT NULL, created_at REAL NOT NULL)""")
    c.commit()
    return c

class Handler(BaseHTTPRequestHandler):
    server_version = "MotifPlanner/0.1"
    def send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def body(self):
        n = int(self.headers.get("Content-Length", "0"))
        if n > 1_000_000: raise ValueError("Payload too large")
        return json.loads(self.rfile.read(n) or b"{}")
    def do_OPTIONS(self):
        self.send(204, {})
    def do_GET(self):
        p = urlparse(self.path).path.strip("/").split("/")
        if p == ["health"]:
            return self.send(200, {"ok": True, "service": "Motif Planner API", "time": time.time()})
        c = connect()
        try:
            if len(p) == 1 and p[0] in ("tasks", "events", "messages", "members"):
                rows = c.execute("SELECT id,payload,updated_at FROM records WHERE kind=? ORDER BY updated_at DESC", (p[0],)).fetchall()
                return self.send(200, {"items":[{"id":r["id"], **json.loads(r["payload"]), "updated_at":r["updated_at"]} for r in rows]})
            if p == ["presence"]:
                rows = c.execute("SELECT member_id,payload,seen_at FROM presence").fetchall()
                return self.send(200, {"items":[{"member_id":r["member_id"], **json.loads(r["payload"]), "seen_at":r["seen_at"]} for r in rows]})
            if len(p) == 2 and p[0] == "calls":
                row = c.execute("SELECT payload FROM calls WHERE id=?", (p[1],)).fetchone()
                return self.send(200, json.loads(row["payload"]) if row else {})
            if len(p) == 2 and p[0] == "calls" and p[1] == "": pass
            if len(p) == 3 and p[0] == "calls" and p[2] == "ice":
                rows = c.execute("SELECT id,sender,payload FROM ice WHERE call_id=? ORDER BY created_at", (p[1],)).fetchall()
                return self.send(200, {"items":[{"id":r["id"],"sender":r["sender"],"candidate":json.loads(r["payload"])} for r in rows]})
            return self.send(404, {"error":"Not found"})
        finally: c.close()
    def do_POST(self):
        p = urlparse(self.path).path.strip("/").split("/")
        try: data = self.body()
        except Exception as e: return self.send(400, {"error":str(e)})
        c = connect()
        try:
            now = time.time()
            if len(p) == 1 and p[0] in ("tasks", "events", "messages", "members"):
                rid = str(data.get("id") or uuid.uuid4())
                c.execute("INSERT INTO records VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at",
                          (rid,p[0],json.dumps(data,ensure_ascii=False),now,now))
                c.commit(); return self.send(201, {"ok":True,"id":rid})
            if p == ["presence"]:
                mid = str(data.get("member_id") or "")
                if not mid: return self.send(400, {"error":"member_id required"})
                c.execute("INSERT INTO presence VALUES(?,?,?) ON CONFLICT(member_id) DO UPDATE SET payload=excluded.payload,seen_at=excluded.seen_at",
                          (mid,json.dumps(data,ensure_ascii=False),now)); c.commit()
                return self.send(200, {"ok":True})
            if p == ["calls"]:
                cid = str(uuid.uuid4()); data.update({"id":cid,"created_at":now})
                c.execute("INSERT INTO calls VALUES(?,?,?)",(cid,json.dumps(data),now)); c.commit()
                return self.send(201, data)
            if len(p) == 3 and p[0] == "calls" and p[2] == "ice":
                iid = str(uuid.uuid4()); sender = str(data.get("sender") or "")
                c.execute("INSERT INTO ice VALUES(?,?,?,?,?)",(iid,p[1],sender,json.dumps(data.get("candidate")),now)); c.commit()
                return self.send(201, {"ok":True,"id":iid})
            return self.send(404, {"error":"Not found"})
        finally: c.close()
    def do_PUT(self):
        p = urlparse(self.path).path.strip("/").split("/")
        if len(p) != 2 or p[0] != "calls": return self.send(404, {"error":"Not found"})
        try: data = self.body()
        except Exception as e: return self.send(400, {"error":str(e)})
        c=connect()
        try:
            c.execute("UPDATE calls SET payload=? WHERE id=?",(json.dumps(data),p[1])); c.commit()
            return self.send(200, {"ok":True})
        finally: c.close()
    def do_DELETE(self):
        p=urlparse(self.path).path.strip("/").split("/")
        if len(p)!=2 or p[0] not in ("tasks","events","messages","members"): return self.send(404,{"error":"Not found"})
        c=connect()
        try:
            c.execute("DELETE FROM records WHERE id=? AND kind=?",(p[1],p[0])); c.commit()
            return self.send(200,{"ok":True})
        finally:c.close()
    def log_message(self, fmt, *args):
        print("%s - %s"%(self.log_date_time_string(),fmt%args))

if __name__ == "__main__":
    connect().close()
    print(f"Motif Planner API listening on http://{HOST}:{PORT}")
    print("WARNING: prototype API has no authentication. Keep it on localhost; do not expose publicly.")
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
