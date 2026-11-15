"""The scam guard (name set by APP_NAME in config.py): one process on the Mac.  Run:  .venv/bin/python app.py

POST /check          used by the Mac app and the iPhone Shortcut
POST /converse       interactive turn (session_id + history)
POST /api/verify     start or respond to trusted-contact verification
GET  /api/verify/pending
GET  /api/patterns   scam-memory incidents
GET  /api/contacts   trusted contacts
GET  /               Grandma's app UI
GET  /family         family dashboard
GET  /events         Server-Sent Events: idle, listening, thinking, safe, suspicious, scam
POST /ask            local only: the "Is this safe?" button (same flow as the wake word)

Flags: --show (keep the window on screen)   --no-window (browser only)   --no-mic (button only)
"""
import asyncio
import faulthandler
import json
import os
import sys
import threading
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
import checker
import config
import listener
import voice
import watcher
from mac import log

app = FastAPI(title=config.APP_NAME)
STATIC = config.ROOT / "static"


class CheckRequest(BaseModel):
    device: str = "iphone"
    question: str = ""
    text: Optional[str] = None
    email: Optional[str] = None
    image_b64: Optional[str] = None


class ConverseRequest(BaseModel):
    utterance: str
    session_id: Optional[str] = None
    speak: bool = False


class VerifyStartRequest(BaseModel):
    headline: str = "Possible impersonation"
    sender: str = "unknown"
    verdict: str = "SCAM"
    reason: str = ""
    contact_name: Optional[str] = None
    use_phrase: bool = False


class VerifyRespondRequest(BaseModel):
    id: Optional[str] = None
    code: Optional[str] = None
    decision: str  # yes / no
    note: Optional[str] = None
    phrase: Optional[str] = None


@app.post("/check")
def check(req: CheckRequest):
    # plain `def`: FastAPI runs it in a worker thread, so Gemini never blocks /events
    return checker.run_check(req.device, req.question, req.text, req.email, req.image_b64)


@app.post("/converse")
def converse(req: ConverseRequest, request: Request):
    """One conversational turn. Keeps a small session history; does not resend the full log to Gemini."""
    if request.client and request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Conversation is local to the Mac.")
    import conversation
    return conversation.turn(req.utterance, session_id=req.session_id, speak=req.speak)


@app.post("/show")
def show(request: Request):
    """Bring the window to the front (used when the app is opened again while running)."""
    if request.client and request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Only from this Mac.")
    if checker.ui_pop:
        checker.ui_pop()
    return {"ok": True}


class AuthRequest(BaseModel):
    first_name: str = ""
    last_name: str = ""
    phone: str = ""
    dob: str = ""
    ticket: str = ""
    password: str = ""
    contact_name: str = ""
    contact_phone: str = ""
    risk_consent: bool = False
    privacy_consent: bool = False


def _local_only(request):
    if request.client and request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Accounts are managed on the Mac itself.")


_AUTH_STEPS = {
    "signup": lambda r: auth.start_signup(r.first_name, r.last_name, r.phone, r.dob),
    "finish": lambda r: auth.finish_signup(r.phone, r.ticket, r.password,
                                           r.contact_name, r.contact_phone,
                                           r.risk_consent, r.privacy_consent),
    "login":  lambda r: auth.login(r.phone, r.password),
    "consent": lambda r: auth.accept_consent(r.risk_consent, r.privacy_consent),
    "forgot": lambda r: auth.start_reset(r.phone, r.dob),
    "reset":  lambda r: auth.reset_password(r.phone, r.ticket, r.password),
    "contact": lambda r: auth.set_contact(r.contact_name, r.contact_phone),
    "logout": lambda r: auth.logout(),
}


@app.get("/api/auth/state")
def auth_state(request: Request):
    _local_only(request)
    return auth.status()


@app.post("/api/auth/{step}")
def auth_step(step: str, req: AuthRequest, request: Request):
    """Sign-up, password, sign-in and reset. Problems the person can
    fix come back as {"ok": false, "error": "..."} to show on screen."""
    _local_only(request)
    if step not in _AUTH_STEPS:
        raise HTTPException(404, "Unknown step.")
    try:
        out = _AUTH_STEPS[step](req)
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}
    return dict(out or {}, ok=True, state=auth.status())


@app.post("/ask")
def ask(request: Request):
    if request.client and request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "The button only works on the Mac itself.")
    if not auth.current():
        raise HTTPException(401, "Please sign in first.")
    # Neutral ask: look at the message first, then judge — don't bias toward "suspicious".
    threading.Thread(
        target=listener.handle,
        args=("Please look at what is on my screen and tell me if it is safe.",),
        kwargs={"ack": False},               # the swipe needs no spoken "Mm-hmm"
        daemon=True,
    ).start()
    return {"ok": True}


@app.get("/api/contacts")
def api_contacts():
    import verify
    contacts = verify.trusted_contacts()
    # Never expose the verification phrase itself.
    return {
        "contacts": [{"name": c.get("name"), "method": c.get("method", "imessage"),
                      "primary": bool(c.get("primary")),
                      "phone_masked": _mask_phone(c.get("phone", ""))} for c in contacts],
        "verify_phrase_configured": bool(config.VERIFY_PHRASE),
        "voice_match_is_not_proof": True,
    }


@app.post("/api/verify/start")
def api_verify_start(req: VerifyStartRequest, request: Request):
    if request.client and request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Starting verification is local to the Mac.")
    import verify
    contact = verify.pick_contact(req.contact_name or "")
    started = verify.start_verification(
        {"headline": req.headline, "sender": req.sender, "verdict": req.verdict,
         "reason": req.reason},
        contact=contact, use_phrase=req.use_phrase or bool(config.VERIFY_PHRASE))
    if not started:
        raise HTTPException(400, "No trusted contact available.")
    return started


@app.post("/api/verify")
def api_verify_respond(req: VerifyRespondRequest):
    """Family confirms or denies an impersonation check (YES/NO + code from iMessage)."""
    import verify
    result = verify.respond(vid=req.id or "", code=req.code or "",
                            decision=req.decision, note=req.note or "",
                            phrase=req.phrase or "")
    if not result:
        raise HTTPException(404, "Verification not found or decision not understood.")
    if result.get("error") == "verification_phrase_required":
        raise HTTPException(400, result["speech"])
    # Speak the outcome on the Mac so Grandma hears it.
    if result.get("speech"):
        threading.Thread(target=voice.speak, args=(result["speech"],), daemon=True).start()
        checker.publish("safe" if result.get("status") == "confirmed" else "scam",
                        headline="Family replied.", reason=result["speech"],
                        verification=result.get("status"))
        checker.idle_later(12)
    return result


@app.get("/api/verify/pending")
def api_verify_pending():
    import verify
    return {"pending": verify.pending_list(), "voice_match_is_not_proof": True}


@app.get("/api/patterns")
def api_patterns(limit: int = 30):
    import memory
    return {
        "incidents": memory.recent_patterns(limit=limit),
        "days": config.SCAM_MEMORY_DAYS,
        "disclaimer": "Pattern matches are illustrative, not verified connections.",
    }


def _mask_phone(phone: str) -> str:
    digits = "".join(c for c in (phone or "") if c.isdigit())
    if len(digits) < 4:
        return "••••"
    return "••••" + digits[-4:]


@app.get("/events")
async def events(request: Request):
    async def stream():
        seq, e = checker.latest_event()
        yield "data: %s\n\n" % json.dumps(e)
        ticks = 0
        while not await request.is_disconnected():
            for s, e in checker.events_since(seq):
                seq = s
                yield "data: %s\n\n" % json.dumps(e)
            await asyncio.sleep(0.15)
            ticks += 1
            if ticks % 100 == 0:
                yield ": keepalive\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC / "icons" / "icon-32.png")


def page(name):
    """Serve an HTML page with the product name filled in."""
    html = (STATIC / name).read_text(encoding="utf-8")
    return HTMLResponse(html.replace("{{NAME}}", config.APP_NAME),
                        headers={"Cache-Control": "no-store"})


@app.get("/")
def home():
    return page("index.html")


@app.get("/family")
def family():
    return page("family.html")


@app.get("/api/checks")
def api_checks(limit: int = 50):
    col = checker.checks_collection()
    if col is None:
        return {"checks": [], "error": "MONGODB_URI not set", "grandma": config.GRANDMA_NAME or "Your family member"}
    try:
        # each person only sees the checks made under their own account
        docs = list(col.find({"user": config.USER_PHONE}, {"_id": 0, "text": 0, "email": 0, "user": 0})
                    .sort("created_at", -1).limit(min(limit, 200)))
    except Exception as e:
        return {"checks": [], "error": str(e), "grandma": config.GRANDMA_NAME or "Your family member"}
    for d in docs:
        d["created_at"] = d["created_at"].isoformat() + "Z"
    return {"checks": docs, "grandma": config.GRANDMA_NAME or "Your family member"}


def main():
    faulthandler.enable()   # if Python ever crashes, print where
    for name in ("GEMINI_API_KEY", "MONGODB_URI"):
        if not getattr(config, name):
            log("WARNING: %s is not set in .env" % name)
    # Stop early with a clear message if Trojan is already running.
    import socket
    probe = socket.socket()
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((config.HOST, config.PORT))
    except OSError:
        # Already running: opening it again just brings the window to the front.
        try:
            import urllib.request
            urllib.request.urlopen(urllib.request.Request(
                "http://127.0.0.1:%d/show" % config.PORT, data=b"", method="POST"), timeout=3)
            log("%s is already running. Brought its window to the front." % config.APP_NAME)
            sys.exit(0)
        except SystemExit:
            raise
        except Exception:
            log("Port %d is already in use by something else. Close it, then start again."
                % config.PORT)
        sys.exit(1)
    finally:
        probe.close()
    auth.migrate_local()        # accounts made before the database was used
    auth.apply_to_config()      # alerts go to the signed-in person's emergency contact
    if not auth.current():
        log("nobody is signed in yet. The window opens so you can sign in.")
    voice.prepare()
    if "--no-mic" not in sys.argv:
        listener.start()
    watcher.start()
    log("Grandma UI:  http://localhost:%d/" % config.PORT)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))   # no packet is sent; just finds our LAN address
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "<this Mac's IP>"
    log("iPhone URL:  http://%s:%d/check" % (ip, config.PORT))
    def serve():
        uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="warning")

    try:
        if "--no-window" in sys.argv:
            serve()                      # browser only: open http://localhost:8000/
        else:
            # The window must own the main thread on macOS, so the server moves to a thread.
            threading.Thread(target=serve, daemon=True, name="trojan-server").start()
            open_window()
    except KeyboardInterrupt:
        pass
    finally:
        # Quit immediately. A normal exit tears down the audio system while the
        # mic thread is still using it, which crashes Python.
        sys.stdout.flush()
        os._exit(0)


def open_window():
    """Grandma's app: a small native macOS window, always on top.

    Like "Hey Siri": by default it waits in the background with no window and no Dock icon,
    appears when it hears its name, and tucks itself away again after answering.
    Closing the window only hides it. Start with --show to keep it on screen instead."""
    import socket
    import time
    background = "--show" not in sys.argv
    start_hidden = background and bool(auth.current())   # consent pending also shows the window   # signed out: show the sign-in screen
    url = "http://127.0.0.1:%d/" % config.PORT
    for _ in range(50):                  # wait up to 5 s for the server to be ready
        try:
            socket.create_connection(("127.0.0.1", config.PORT), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    try:
        import webview
        window = webview.create_window(config.APP_NAME, url, width=420, height=660,
                                       min_size=(380, 600), on_top=True, hidden=start_hidden,
                                       background_color="#F5F0E1", text_select=False)
        state = {"visible": not start_hidden}

        def hide():
            """Take the window off screen (used before the screenshot, and when tucking away)."""
            if not state["visible"]:
                return
            try:
                window.hide()
                state["visible"] = False
                time.sleep(0.35)             # let macOS finish removing it from the screen
            except Exception as e:
                log("could not hide window:", e)

        def pop():
            """Bring the window up in front of everything."""
            try:
                window.restore()
                window.show()
                state["visible"] = True
                import AppKit
                from PyObjCTools import AppHelper
                AppHelper.callAfter(lambda: AppKit.NSApp.activateIgnoringOtherApps_(True))
            except Exception as e:
                log("could not pop window:", e)

        def on_closing():
            if not background:
                return True                  # --show mode: closing the window quits
            state["visible"] = False
            window.hide()
            log("window hidden. Still listening for \"Hey %s\". Ctrl+C here quits." % config.APP_NAME)
            return False                     # cancel the close: keep running in the background

        def tuck_away():
            """Background mode: hide again a little while after the answer."""
            was_busy = False
            while True:
                time.sleep(1)
                st = checker.latest_event()[1].get("state")
                if st != "idle":
                    was_busy = True
                elif was_busy and state["visible"] and auth.current():
                    was_busy = False
                    time.sleep(TUCK_AWAY_SECONDS)
                    if checker.latest_event()[1].get("state") == "idle":
                        hide()

        def quit_on_signals():
            # Ctrl+C / kill must still quit, even though closing the window only hides it.
            import signal
            from PyObjCTools import MachSignals
            for sig in (signal.SIGINT, signal.SIGTERM):
                MachSignals.signal(sig, lambda signum: os._exit(0))

        def started():
            try:
                from PyObjCTools import AppHelper
                AppHelper.callAfter(quit_on_signals)
            except Exception as e:
                log("could not install Ctrl+C handler:", e)
            if background:
                try:                         # no Dock icon while waiting in the background
                    import AppKit
                    from PyObjCTools import AppHelper
                    AppHelper.callAfter(lambda: AppKit.NSApp.setActivationPolicy_(1))
                except Exception as e:
                    log("could not hide Dock icon:", e)
                threading.Thread(target=tuck_away, daemon=True).start()
                log("running in the background. Say \"Hey %s\" and it appears. "
                    "Ctrl+C here quits." % config.APP_NAME)
            else:
                log("app window open. Close it (or press Ctrl+C here) to quit.")

        window.events.closing += on_closing
        checker.ui_hide, checker.ui_pop = hide, pop
        webview.start(started)
    except Exception as e:
        log("could not open the app window (%s). Opening the browser instead." % e)
        import webbrowser
        webbrowser.open(url)
        threading.Event().wait()         # keep serving until Ctrl+C


TUCK_AWAY_SECONDS = 5    # after the answer is done, stay this long, then vanish (like Siri)


if __name__ == "__main__":
    main()
