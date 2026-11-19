"""Life Certificate Reminder Caller (with PIN login)
Upload a CSV (name,phone) -> app calls each person and plays a voice reminder.

Environment variables:
  APP_PIN      login PIN/password for the web page (REQUIRED when Twilio keys are set)
  SECRET_KEY   long random string, keeps logins valid across restarts
  TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM
  PUBLIC_URL   https address of this app, no trailing slash (needed for "press 1" and retries)
Run locally: pip install flask twilio ; python app.py
Production:  gunicorn app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT
Without Twilio keys it runs in DRY-RUN mode (no real calls) for testing.
"""
import csv, io, os, re, threading, time, hmac, secrets
from datetime import datetime, timedelta
from urllib.parse import quote
from markupsafe import escape
from flask import Flask, request, jsonify, render_template_string, Response, session, redirect

app = Flask(__name__)
SID, TOKEN, FROM = (os.getenv(k) for k in ("TWILIO_SID", "TWILIO_TOKEN", "TWILIO_FROM"))
LIVE = all([SID, TOKEN, FROM])
PUBLIC = (os.getenv("PUBLIC_URL") or "").rstrip("/")
PIN = os.getenv("APP_PIN", "")
MAX_ROUNDS = int(os.getenv("MAX_ROUNDS", "3"))      # first try + 2 retries
RETRY_GAP = int(os.getenv("RETRY_GAP_SECONDS", "600"))  # wait before retrying
RETRY_STATES = ("no-answer", "busy", "failed", "canceled")

if LIVE and not PIN:
    raise SystemExit("Set APP_PIN before running with Twilio keys, otherwise anyone could start calls.")

app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=PUBLIC.startswith("https"),
                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))

client = validator = None
if LIVE:
    from twilio.rest import Client
    from twilio.request_validator import RequestValidator
    client = Client(SID, TOKEN)
    validator = RequestValidator(TOKEN)

JOBS = {"rows": [], "running": False, "msg": "", "lang": "hi-IN"}
LOG = "call_log.csv"
FAILS = {}  # ip -> (failed count, locked-until timestamp)

TWILIO_HOOKS = {"/voice", "/gather", "/callback"}
OPEN_PATHS = {"/login", "/manifest.json", "/sw.js", "/icon.png"}

DEFAULT_MSG = {
    "hi-IN": "नमस्ते {name}। यह जिला ट्रेज़री कार्यालय राजौरी की ओर से सूचना है। कृपया दो दिनों के भीतर अपना डिजिटल जीवन प्रमाण पत्र जमा करें, अन्यथा आपकी पेंशन बंद हो जाएगी।",
    "en-IN": "Hello {name}. This is a message from the District Treasury Office, Rajouri. Please update your digital life certificate within two days, otherwise your pension will stop.",
}

# ---------- security ----------
def client_ip():
    return (request.headers.get("X-Forwarded-For") or request.remote_addr or "?").split(",")[0].strip()

def twilio_ok():
    qs = request.query_string.decode()
    url = PUBLIC + request.path + ("?" + qs if qs else "")
    sig = request.headers.get("X-Twilio-Signature", "")
    return validator.validate(url, request.form.to_dict(), sig)

@app.before_request
def guard():
    p = request.path
    if p in TWILIO_HOOKS:  # called by Twilio, not by a person: check Twilio's signature
        if LIVE and PUBLIC and not twilio_ok():
            return Response("Forbidden", 403)
        return None
    if p in OPEN_PATHS or not PIN or session.get("ok"):
        return None
    if p == "/":
        return redirect("/login")
    return jsonify(error="login required"), 401

@app.route("/login", methods=["GET", "POST"])
def login():
    if not PIN:
        return redirect("/")
    err = ""
    if request.method == "POST":
        k = client_ip()
        n, until = FAILS.get(k, (0, 0))
        if time.time() < until:
            err = "Too many attempts. Try again in 5 minutes."
        elif hmac.compare_digest(request.form.get("pin", "").encode(), PIN.encode()):
            FAILS.pop(k, None)
            session.permanent = True
            session["ok"] = True
            return redirect("/")
        else:
            n += 1
            FAILS[k] = (0, time.time() + 300) if n >= 5 else (n, 0)
            err = "Wrong PIN."
    return render_template_string(LOGIN_PAGE, err=err)

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------- calling logic ----------
def norm(p):
    d = re.sub(r"\D", "", p or "")
    if len(d) == 10: return "+91" + d
    if len(d) == 12 and d.startswith("91"): return "+" + d
    return None

def by_sid(sid):
    return next((r for r in JOBS["rows"] if r.get("sid") == sid), None)

def log(r):
    with open(LOG, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([datetime.now().isoformat(timespec="seconds"), r["name"], r["phone"], r["attempts"], r["status"]])

def place(r, lang, template):
    text = escape(template.replace("{name}", r["name"]))
    r["attempts"] += 1
    r["status"] = "calling"
    try:
        if not LIVE:
            time.sleep(0.5); r["status"] = "dry-run"; log(r); return
        if PUBLIC:
            c = client.calls.create(to=r["phone"], from_=FROM, url=f"{PUBLIC}/voice?n={quote(r['name'])}",
                                    status_callback=f"{PUBLIC}/callback",
                                    status_callback_event=["completed"])
        else:  # no public address: plain message, no keypress, no status updates
            tw = f'<Response><Say language="{lang}">{text}</Say></Response>'
            c = client.calls.create(to=r["phone"], from_=FROM, twiml=tw)
            r["status"] = "called"
        r["sid"] = c.sid
    except Exception as e:
        r["status"] = "failed"; r["error"] = str(e)[:80]

def worker(lang, template, delay):
    for rnd in range(MAX_ROUNDS):
        for r in JOBS["rows"]:
            if r["status"] == "pending":
                place(r, lang, template)
                time.sleep(delay)
        if not (LIVE and PUBLIC): break
        for _ in range(60):  # wait up to ~2 min for call results
            if not any(r["status"] == "calling" for r in JOBS["rows"]): break
            time.sleep(2)
        for r in JOBS["rows"]:
            if r["status"] in RETRY_STATES: log(r)
        retry = [r for r in JOBS["rows"] if r["status"] in RETRY_STATES]
        if not retry or rnd == MAX_ROUNDS - 1: break
        time.sleep(RETRY_GAP)
        for r in retry: r["status"] = "pending"
    for r in JOBS["rows"]:
        if r["status"] in ("answered", "confirmed"): log(r)
    JOBS["running"] = False

@app.post("/voice")
@app.get("/voice")
def voice():
    name, lang = request.args.get("n", ""), JOBS["lang"]
    text = escape(JOBS["msg"].replace("{name}", name))
    prompt = {"hi-IN": "पुष्टि करने के लिए एक दबाएं।", "en-IN": "Press 1 to confirm you have received this message."}[lang]
    return Response(f'''<Response><Gather numDigits="1" timeout="6" action="{PUBLIC}/gather">
<Say language="{lang}">{text}</Say><Say language="{lang}">{prompt}</Say></Gather>
<Say language="{lang}">{text}</Say></Response>''', mimetype="text/xml")

@app.post("/gather")
def gather():
    r = by_sid(request.form.get("CallSid"))
    lang = JOBS["lang"]
    if request.form.get("Digits") == "1":
        if r: r["status"] = "confirmed"
        thanks = {"hi-IN": "धन्यवाद।", "en-IN": "Thank you."}[lang]
        return Response(f'<Response><Say language="{lang}">{thanks}</Say></Response>', mimetype="text/xml")
    return Response("<Response/>", mimetype="text/xml")

@app.post("/callback")
def callback():
    r = by_sid(request.form.get("CallSid"))
    st = request.form.get("CallStatus")
    if r and r["status"] != "confirmed":
        r["status"] = "answered" if st == "completed" else st
    return ("", 204)

@app.post("/upload")
def upload():
    data = request.files["file"].read().decode("utf-8-sig")
    rows, bad, seen = [], 0, set()
    table = list(csv.reader(io.StringIO(data)))
    head = [h.strip().lower() for h in table[0]] if table else []
    if "phone" in head or "mobile" in head:  # file has a header row
        ni = head.index("name") if "name" in head else None
        pi = head.index("phone") if "phone" in head else head.index("mobile")
        body = table[1:]
    else:  # no header: first column name, second column phone
        ni, pi, body = 0, 1, table
    for r in body:
        ph = norm(r[pi]) if len(r) > pi else None
        if ph and ph not in seen:
            seen.add(ph)
            name = re.sub(r"\s+", " ", r[ni]).strip() if ni is not None and len(r) > ni else ""
            rows.append({"name": name, "phone": ph, "status": "pending", "attempts": 0})
        else: bad += 1
    JOBS["rows"] = rows
    return jsonify(count=len(rows), invalid=bad, live=LIVE, defaults=DEFAULT_MSG)

@app.post("/start")
def start():
    if JOBS["running"]: return jsonify(error="Already running"), 409
    j = request.json
    if j.get("lang") not in DEFAULT_MSG: return jsonify(error="Bad language"), 400
    JOBS["running"] = True
    JOBS["msg"], JOBS["lang"] = j["message"], j["lang"]
    threading.Thread(target=worker, args=(j["lang"], j["message"], 3), daemon=True).start()
    return jsonify(ok=True)

@app.get("/status")
def status():
    return jsonify(rows=JOBS["rows"], running=JOBS["running"])

# ---------- PWA files ----------
@app.get("/manifest.json")
def manifest():
    return jsonify(name="Life certificate calls", short_name="LC Calls", start_url="/", display="standalone",
                   background_color="#f6f7f9", theme_color="#14532d",
                   icons=[{"src": "/icon.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}])

@app.get("/sw.js")
def sw():
    return Response("self.addEventListener('fetch',()=>{});", mimetype="text/javascript")

@app.get("/icon.png")
def icon():  # plain green square with a white phone-like block, built without extra libraries
    import zlib, struct
    n = 512
    rows = b"".join(b"\x00" + b"".join((b"\xff\xff\xff" if 180 < x < 332 and 140 < y < 372 else b"\x14\x53\x2d") for x in range(n)) for y in range(n))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")
    return Response(png, mimetype="image/png")

@app.get("/")
def home():
    return render_template_string(PAGE, live=LIVE, public=bool(PUBLIC), pin=bool(PIN))

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title>
<link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#14532d">
<style>body{font-family:system-ui,sans-serif;max-width:360px;margin:0 auto;padding:16px;background:#f6f7f9;color:#1c2430}
h1{font-size:1.3rem}.box{background:#fff;border:1px solid #d9dee5;border-radius:8px;padding:14px;margin:12px 0}
input{width:100%;box-sizing:border-box;font:inherit;padding:10px;margin:8px 0}
button{background:#14532d;color:#fff;border:0;border-radius:6px;padding:11px 16px;font:inherit;width:100%}
.err{color:#b91c1c}</style></head><body>
<h1>Life certificate calls</h1>
<form class="box" method="post"><b>Enter PIN</b>
<input type="password" name="pin" autofocus autocomplete="current-password" required>
{% if err %}<div class="err">{{ err }}</div>{% endif %}
<button>Log in</button></form></body></html>"""

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Life certificate calls</title><link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#14532d">
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:0 auto;padding:16px;background:#f6f7f9;color:#1c2430}
h1{font-size:1.3rem;margin:.2em 0}.box{background:#fff;border:1px solid #d9dee5;border-radius:8px;padding:14px;margin:12px 0}
textarea,select,input[type=file]{width:100%;box-sizing:border-box;margin:6px 0;font:inherit;padding:8px}
textarea{height:110px}button{background:#14532d;color:#fff;border:0;border-radius:6px;padding:11px 16px;font:inherit;width:100%}
button:disabled{opacity:.4}table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{padding:6px;border-bottom:1px solid #e6e9ee;text-align:left}
.tag{font-size:.8rem;padding:2px 8px;border-radius:10px;background:{{ '#dcfce7' if live else '#fef3c7' }}}
</style></head><body>
<h1>Life certificate reminder calls</h1>
<span class="tag">{{ 'Live calling' if live else 'Dry-run: no real calls (add Twilio keys)' }}</span>{% if live and not public %} <small>Set PUBLIC_URL to enable press-1 and retries.</small>{% endif %}{% if pin %} <small><a href="/logout">Log out</a></small>{% endif %}
<div class="box"><b>1. Upload contact list</b><br><small>CSV with columns: name, phone</small>
<input type="file" id="f" accept=".csv"><div id="info"></div></div>
<div class="box"><b>2. Message</b>
<select id="lang"><option value="hi-IN">Hindi</option><option value="en-IN">English</option></select>
<textarea id="msg"></textarea><small>{name} is replaced with each person's name.</small></div>
<button id="go" disabled>Start calling</button>
<div class="box"><table><thead><tr><th>Name</th><th>Phone</th><th>Status</th></tr></thead><tbody id="t"></tbody></table></div>
<script>
if("serviceWorker" in navigator)navigator.serviceWorker.register("/sw.js");
let D={};const $=i=>document.getElementById(i);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(u,o){const r=await fetch(u,o);if(r.status==401){location='/login';throw new Error('login')}return r}
$('f').onchange=async e=>{const fd=new FormData();fd.append('file',e.target.files[0]);
const r=await(await api('/upload',{method:'POST',body:fd})).json();D=r.defaults;
$('info').textContent=r.count+' valid numbers, '+r.invalid+' skipped';$('msg').value=D[$('lang').value];$('go').disabled=!r.count;poll()};
$('lang').onchange=()=>$('msg').value=D[$('lang').value];
$('go').onclick=async()=>{if(!confirm('Start calling everyone on the list?'))return;
await api('/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lang:$('lang').value,message:$('msg').value})});poll()};
async function poll(){const r=await(await api('/status')).json();
$('t').innerHTML=r.rows.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.phone)}</td><td>${esc(x.status)}${x.attempts>1?' (try '+x.attempts+')':''}</td></tr>`).join('');
const c=k=>r.rows.filter(x=>x.status==k).length;if(r.rows.length)$('info').textContent=r.rows.length+' contacts · confirmed '+c('confirmed')+' · answered '+c('answered')+' · no answer '+c('no-answer');
if(r.running)setTimeout(poll,2000)}
</script></body></html>"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
