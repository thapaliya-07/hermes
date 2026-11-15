"""Everything that touches macOS: read the latest text / email / screen, speak,
send an iMessage, open FaceTime. The app only READS Grandma's messages. It never
replies to, deletes, or clicks anything."""
import os
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import config

CHAT_DB = Path.home() / "Library" / "Messages" / "chat.db"
_OWN_ALERTS = tuple("%s %s" % (n, k) for n in (config.APP_NAME, "Hermes", "Moly", "Trojan")
                    for k in ("alert.", "check-in.", "FYI.", "here."))
APPLE_EPOCH = 978307200  # seconds between 1970-01-01 and 2001-01-01


def log(*a):
    print("[%s]" % config.APP_NAME.lower(), *a, flush=True)


# ---------- latest text message (read-only) ----------

def _decode_attributed_body(blob):
    """Newer macOS stores the message in `attributedBody` (a typedstream blob)
    instead of `text`. The string sits right after the NSString marker."""
    if not blob:
        return ""
    try:
        i = blob.find(b"NSString")
        if i < 0:
            return ""
        rest = blob[i + 8:]
        j = rest.find(b"+")
        if j < 0:
            return ""
        rest = rest[j + 1:]
        n = rest[0]
        start = 1
        if n == 0x81:  # 2-byte length follows
            n = int.from_bytes(rest[1:3], "little")
            start = 3
        elif n == 0x82:  # 4-byte length follows
            n = int.from_bytes(rest[1:5], "little")
            start = 5
        return rest[start:start + n].decode("utf-8", "replace").strip()
    except Exception:
        return ""


def latest_text():
    """Returns {"sender", "body", "minutes_ago"} for the newest INCOMING text,
    or None. Needs Full Disk Access for the app that runs Python."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % CHAT_DB, uri=True, timeout=3)
        rows = con.execute(
            "SELECT m.text, m.attributedBody, h.id, m.date "
            "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "WHERE m.is_from_me = 0 ORDER BY m.date DESC LIMIT 25"
        ).fetchall()
        con.close()
    except Exception as e:
        log("could not read Messages (grant Full Disk Access?):", e)
        return None
    for text, blob, sender, date in rows:
        body = (text or "").strip() or _decode_attributed_body(blob)
        if not body or body == "￼":
            continue
        if any(tag in body[:48] for tag in _OWN_ALERTS):
            continue   # our own family alert, not something Grandma received
        secs = date / 1e9 if date and date > 1e12 else (date or 0)
        mins = max(0, int((time.time() - (secs + APPLE_EPOCH)) / 60))
        return {"sender": sender or "unknown number", "body": body[:3000], "minutes_ago": mins}
    return None


# ---------- latest email (Mail.app via AppleScript) ----------

_MAIL_SCRIPT = '''
if application "Mail" is not running then return ""
tell application "Mail"
    set msgs to messages of inbox
    if (count of msgs) is 0 then return ""
    set m to item 1 of msgs
    set body to content of m
    if (length of body) > 3000 then set body to text 1 thru 3000 of body
    return (sender of m) & "\n" & (subject of m) & "\n" & body
end tell
'''


def latest_email():
    """Returns {"sender", "subject", "body"} for the newest inbox email, or None.
    Mail.app must be open (we never launch it or change anything in it)."""
    try:
        r = subprocess.run(["osascript", "-e", _MAIL_SCRIPT],
                           capture_output=True, text=True, timeout=20)
    except Exception as e:
        log("could not read Mail:", e)
        return None
    if r.returncode != 0:
        log("could not read Mail:", r.stderr.strip())
        return None
    out = r.stdout.strip("\n")
    if not out.strip():
        return None
    parts = out.split("\n", 2) + ["", ""]
    return {"sender": parts[0].strip(), "subject": parts[1].strip(), "body": parts[2].strip()}


# ---------- screenshot ----------

def screenshot():
    """Returns JPEG bytes of the screen, or None. Needs Screen Recording permission."""
    path = os.path.join(tempfile.gettempdir(), "guard_screen.jpg")
    try:
        subprocess.run(["screencapture", "-x", "-t", "jpg", path], check=True, timeout=10)
        # shrink so the upload to Gemini is fast
        subprocess.run(["sips", "-Z", "1600", path], capture_output=True, timeout=10)
        with open(path, "rb") as f:
            data = f.read()
        os.remove(path)
        return data
    except Exception as e:
        log("could not take screenshot (grant Screen Recording?):", e)
        return None


# ---------- voice ----------

_voice_cache = None
_speak_lock = threading.Lock()


def best_voice():
    """TROJAN_VOICE from .env, otherwise the best installed English voice."""
    global _voice_cache
    if _voice_cache is not None:
        return _voice_cache
    if config.TROJAN_VOICE:
        _voice_cache = config.TROJAN_VOICE
        return _voice_cache
    names = []
    try:
        out = subprocess.run(["say", "-v", "?"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            head = line.split("#")[0].rstrip()
            bits = head.rsplit(None, 1)
            if len(bits) == 2 and bits[1].startswith("en_"):
                names.append(bits[0].strip())
    except Exception:
        pass
    pick = ""
    for tag in ("(Premium)", "(Enhanced)"):
        for n in names:
            if tag in n:
                pick = n
                break
        if pick:
            break
    _voice_cache = pick or ("Samantha" if "Samantha" in names else "")
    log("voice:", _voice_cache or "system default")
    return _voice_cache


def say(text):
    """Speak out loud and wait until finished. Never raises."""
    if not text:
        return
    cmd = ["say", "-r", str(config.TROJAN_RATE)]
    v = best_voice()
    if v:
        cmd += ["-v", v]
    with _speak_lock:
        try:
            subprocess.run(cmd + [text], timeout=60)
        except Exception as e:
            log("say failed:", e)


# ---------- family alerts ----------

_IMESSAGE_SCRIPT = '''
on run {target, msg}
    tell application "Messages"
        try
            set acct to 1st account whose service type = iMessage
            send msg to participant target of acct
        on error
            set svc to 1st service whose service type = iMessage
            send msg to buddy target of svc
        end try
    end tell
end run
'''


def send_imessage(phone, message):
    """Send one iMessage to the family. Returns True on success."""
    if not phone:
        log("FAMILY_PHONE not set, skipping iMessage")
        return False
    try:
        r = subprocess.run(["osascript", "-e", _IMESSAGE_SCRIPT, phone, message],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            log("iMessage failed:", r.stderr.strip())
            return False
        log("iMessage sent to family")
        return True
    except Exception as e:
        log("iMessage failed:", e)
        return False


def open_facetime(phone):
    if not phone:
        return
    try:
        subprocess.run(["open", "facetime://" + phone.replace(" ", "")], timeout=10)
    except Exception as e:
        log("FaceTime failed:", e)
