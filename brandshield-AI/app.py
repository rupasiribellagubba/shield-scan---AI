import json, os, sqlite3, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from flask import Flask, g, jsonify, request
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from scanner import InvalidURL, scan_url

SCHEMA = """CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, host TEXT,
score INTEGER, level TEXT, mode TEXT, findings TEXT, intel TEXT, advice TEXT, created_at TEXT)"""


def create_app(db_path=None):
    app = Flask(__name__, static_folder="static", static_url_path="")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.config["DB"] = db_path or os.getenv("DATABASE_PATH", "scans.db")
    hits = defaultdict(list)

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close(_):
        d = g.pop("db", None)
        if d is not None:
            d.close()

    with app.app_context():
        db().execute(SCHEMA)
        db().commit()

    @app.after_request
    def headers(r):
        r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Referrer-Policy"] = "no-referrer"
        return r

    def limited():
        now, ip = time.time(), request.remote_addr
        hits[ip] = [t for t in hits[ip] if now - t < 60]
        hits[ip].append(now)
        return len(hits[ip]) > 40

    def save(res, mode):
        cur = db().execute("INSERT INTO scans(url,host,score,level,mode,findings,intel,advice,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                           (res["url"], res["host"], res["score"], res["level"], mode, json.dumps(res["findings"]),
                            json.dumps(res["intel"]), res["advice"], datetime.now(timezone.utc).isoformat(timespec="seconds")))
        db().commit()
        return cur.lastrowid

    def mode_of(v):
        return v if v in ("individual", "company") else "individual"

    @app.get("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.post("/api/scan")
    def scan():
        if limited():
            return jsonify(error="Too many scans. Please wait a minute."), 429
        data = request.get_json(silent=True) or {}
        mode = mode_of(data.get("mode"))
        try:
            res = scan_url(data.get("url"))
        except InvalidURL as e:
            return jsonify(error=str(e)), 400
        res["id"] = save(res, mode)
        return jsonify(res), 201

    @app.post("/api/scan/bulk")
    def bulk():
        if limited():
            return jsonify(error="Too many scans. Please wait a minute."), 429
        urls = (request.get_json(silent=True) or {}).get("urls")
        if not isinstance(urls, list) or not 1 <= len(urls) <= 20:
            return jsonify(error="Send between 1 and 20 URLs."), 400
        results = []
        for u in urls:
            try:
                res = scan_url(u)
                res["id"] = save(res, "company")
                results.append({"url": res["url"], "score": res["score"], "level": res["level"], "id": res["id"]})
            except InvalidURL as e:
                results.append({"url": str(u)[:200], "error": str(e)})
        return jsonify(results=results), 201

    @app.get("/api/history")
    def history():
        mode = request.args.get("mode")
        try:
            limit = max(1, min(100, int(request.args.get("limit", 25))))
        except ValueError:
            limit = 25
        sql, args = "SELECT id,url,score,level,mode,created_at FROM scans", []
        if mode in ("individual", "company"):
            sql += " WHERE mode=?"
            args.append(mode)
        rows = db().execute(sql + " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()
        return jsonify(scans=[dict(r) for r in rows])

    @app.get("/api/scan/<int:sid>")
    def detail(sid):
        r = db().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if r is None:
            return jsonify(error="Scan not found."), 404
        d = dict(r)
        d["findings"], d["intel"] = json.loads(d["findings"]), json.loads(d["intel"])
        d["disclaimer"] = "Risk scores are estimates from URL patterns, not proof that a site is safe or malicious."
        return jsonify(d)

    @app.get("/api/stats")
    def stats():
        mode = mode_of(request.args.get("mode", "company"))
        q = lambda sql: db().execute(sql, (mode,)).fetchall()
        t = q("SELECT COUNT(*) c, COALESCE(AVG(score),0) a FROM scans WHERE mode=?")[0]
        levels = {r["level"]: r["c"] for r in q("SELECT level, COUNT(*) c FROM scans WHERE mode=? GROUP BY level")}
        daily = q("SELECT substr(created_at,1,10) d, COUNT(*) c FROM scans WHERE mode=? GROUP BY d ORDER BY d DESC LIMIT 7")
        top = Counter(f["label"] for r in q("SELECT findings FROM scans WHERE mode=? ORDER BY id DESC LIMIT 500")
                      for f in json.loads(r["findings"]))
        high = q("SELECT id,url,score,created_at FROM scans WHERE mode=? AND level='High' ORDER BY id DESC LIMIT 5")
        return jsonify(total=t["c"], average_score=round(t["a"], 1),
                       levels={k: levels.get(k, 0) for k in ("Low", "Medium", "High")},
                       daily=[dict(r) for r in reversed(daily)], top_indicators=top.most_common(5),
                       recent_high_risk=[dict(r) for r in high])

    @app.errorhandler(404)
    def nf(_):
        return jsonify(error="Not found."), 404

    @app.errorhandler(413)
    def big(_):
        return jsonify(error="Request too large."), 413

    @app.errorhandler(405)
    def na(_):
        return jsonify(error="Method not allowed."), 405

    @app.errorhandler(Exception)
    def boom(e):
        app.logger.exception(e)
        return jsonify(error="Something went wrong on our side. Please try again."), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", 5000)))
