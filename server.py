"""Hermes on the web: the hosted server behind the iPhone (and any browser).

Run:  uvicorn server:app --host 0.0.0.0 --port $PORT

It shares the accounts and the check pipeline with the Mac app, but it cannot read
anyone's messages: a person signs in, then shows it a screenshot or pastes a message.
Each browser has its own sign-in (a cookie), stored in MongoDB so it survives restarts.
The silent background guard and the wake word only exist in the Mac app (app.py)."""
import hashlib
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
import checker
import config
from mac import log

app = FastAPI(title=config.APP_NAME)
STATIC = config.ROOT / "static"
COOKIE = "hermes_session"
SESSION_DAYS = 30
MAX_IMAGE_CHARS = 8_000_000      # about 6 MB of picture, as base64
MAX_TEXT_CHARS = 6000
CHECKS_PER_MINUTE = 6            # per person: protects the free Gemini quota


# ---------- sessions: one per browser ----------

_memory_sessions = {}            # used only when there is no MONGODB_URI (local testing)


def _sessions():
    col = checker.checks_collection()
    return None if col is None else col.database["sessions"]


def _key(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _session_phone(token):
    """The phone this cookie is signed in as, or ''."""
    if not token:
        return ""
    col = _sessions()
    if col is None:
        row = _memory_sessions.get(_key(token))
    else:
        row = col.find_one({"_id": _key(token)})
    if not row or row["expires"].replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return ""
    return row["phone"]


def _session_start(phone):
    token = secrets.token_urlsafe(32)
    row = {"_id": _key(token), "phone": phone,
           "expires": datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)}
    col = _sessions()
    if col is None:
        _memory_sessions[row["_id"]] = row
    else:
        col.insert_one(row)
    return token


def _session_end(token):
    if not token:
        return
    col = _sessions()
    if col is None:
        _memory_sessions.pop(_key(token), None)
    else:
        col.delete_one({"_id": _key(token)})


class _Signed:
    """Handle one request as the person this browser is signed in as."""

    def __init__(self, request, response=None):
        self.request, self.response = request, response
        self.token = request.cookies.get(COOKIE, "")

    def __enter__(self):
        phone = _session_phone(self.token)
        self.web = {"user": auth.get_account(phone) if phone else None, "changed": False}
        self._reset = auth._web.set(self.web)
        return self

    def __exit__(self, exc_type, exc, tb):
        auth._web.reset(self._reset)
        if exc_type or not self.web["changed"] or self.response is None:
            return False
        _session_end(self.token)                      # signing in or out replaces the cookie
        if self.web["user"]:
            secure = (self.request.headers.get("x-forwarded-proto", self.request.url.scheme)
                      == "https")
            self.response.set_cookie(
                COOKIE, _session_start(self.web["user"]["phone"]), httponly=True, secure=secure,
                samesite="lax", max_age=SESSION_DAYS * 86400, path="/")
        else:
            self.response.delete_cookie(COOKIE, path="/")
        return False


# ---------- accounts ----------

@app.get("/api/auth/state")
def auth_state(request: Request):
    with _Signed(request):
        return auth.status()


@app.post("/api/auth/{step}")
def auth_step(step: str, request: Request, response: Response, body: dict = Body(default={})):
    if step not in auth.STEPS:
        raise HTTPException(404, "Unknown step.")
    with _Signed(request, response):
        return auth.run_step(step, body)


# ---------- the check ----------

class WebCheck(BaseModel):
    text: Optional[str] = None
    image_b64: Optional[str] = None


_recent = {}                     # phone -> times of their last checks
_recent_lock = threading.Lock()


def _allow(phone):
    now = time.time()
    with _recent_lock:
        times = [t for t in _recent.get(phone, []) if now - t < 60]
        if len(times) >= CHECKS_PER_MINUTE:
            _recent[phone] = times
            return False
        _recent[phone] = times + [now]
        return True


def _alert_text(user, r):
    """A ready-to-send text for the emergency contact. The person sends it themself."""
    who = user.get("first_name") or user.get("name") or "I"
    kind = "a scam" if r["verdict"] == "SCAM" else "suspicious"
    return ("Hi %s, this is %s. %s checked a message I got and says it looks like %s. %s "
            "Could you call me?" % (user.get("contact_name") or "there", who,
                                    config.APP_NAME, kind, r.get("reason", "")))


@app.post("/api/check")
def api_check(req: WebCheck, request: Request):
    """Check a pasted message or a screenshot for the signed-in person."""
    with _Signed(request):
        user = auth.current()
    if not user:
        raise HTTPException(401, "Please sign in first.")
    text = (req.text or "").strip()[:MAX_TEXT_CHARS]
    image = req.image_b64 or ""
    if not text and not image:
        raise HTTPException(400, "Add a screenshot or paste the message first.")
    if len(image) > MAX_IMAGE_CHARS:
        raise HTTPException(413, "That picture is too large. Try a screenshot instead.")
    if not _allow(user["phone"]):
        raise HTTPException(429, "Please wait a moment before the next check.")
    question = ("Is this safe? Look at the pasted message." if text and not image
                else "Is this safe? Look at the screenshot.")
    r = checker.run_check("iphone", question, text=text or None, image_b64=image or None,
                          silent=True, skip_memory=True, user=user["phone"], notify=False)
    out = {k: r.get(k) for k in ("verdict", "speech", "item", "sender", "headline", "reason",
                                 "action", "scene")}
    out["failed"] = bool(r.get("error"))
    if r["verdict"] in ("SCAM", "SUSPICIOUS") and not r.get("error") and user.get("contact_phone"):
        out["contact"] = {"name": user.get("contact_name", ""), "phone": user["contact_phone"],
                          "message": _alert_text(user, r)}
    return out


@app.get("/api/checks")
def api_checks(request: Request, limit: int = 50):
    """The signed-in person's own history (for the dashboard)."""
    with _Signed(request):
        user = auth.current()
    if not user:
        raise HTTPException(401, "Please sign in first.")
    col = checker.checks_collection()
    if col is None:
        return {"checks": [], "grandma": user["name"]}
    docs = list(col.find({"user": user["phone"]}, {"_id": 0, "text": 0, "email": 0, "user": 0})
                .sort("created_at", -1).limit(min(limit, 200)))
    for d in docs:
        d["created_at"] = d["created_at"].isoformat() + "Z"
        d.pop("expires_at", None)
    return {"checks": docs, "grandma": user["name"]}


# ---------- pages ----------

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "icons" / "icon-32.png")


def page(name):
    html = (STATIC / name).read_text(encoding="utf-8")
    return HTMLResponse(html.replace("{{NAME}}", config.APP_NAME).replace("{{MODE}}", "web"),
                        headers={"Cache-Control": "no-store"})


@app.get("/")
def home():
    return page("index.html")


@app.get("/family")
def family():
    return page("family.html")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


for _name in ("GEMINI_API_KEY", "MONGODB_URI"):
    if not getattr(config, _name):
        log("WARNING: %s is not set" % _name)
