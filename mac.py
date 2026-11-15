"""Everything that touches macOS: read the latest text / screen, speak,
send an iMessage, open FaceTime. The app only READS Grandma's messages. It never
replies to, deletes, or clicks anything. It does not read Mail."""
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
                    for k in ("alert.", "check-in.", "FYI.", "here.", "code:"))
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
    """Returns {"sender", "body", "minutes_ago", "known"} for the newest INCOMING text,
    or None. Needs Full Disk Access for the app that runs Python."""
    try:
        con = sqlite3.connect("file:%s?mode=ro" % CHAT_DB, uri=True, timeout=3)
        rows = con.execute(
            "SELECT m.text, m.attributedBody, h.id, m.date, "
            "  (SELECT COUNT(*) FROM message o WHERE o.handle_id = m.handle_id "
            "   AND o.is_from_me = 1) "
            "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "WHERE m.is_from_me = 0 ORDER BY m.date DESC LIMIT 25"
        ).fetchall()
        con.close()
    except Exception as e:
        log("could not read Messages (grant Full Disk Access?):", e)
        return None
    for text, blob, sender, date, replies in rows:
        body = (text or "").strip() or _decode_attributed_body(blob)
        if not body or body == "￼":
            continue
        if any(tag in body[:48] for tag in _OWN_ALERTS):
            continue   # our own family alert, not something Grandma received
        secs = date / 1e9 if date and date > 1e12 else (date or 0)
        mins = max(0, int((time.time() - (secs + APPLE_EPOCH)) / 60))
        # "known" = she has written back to this sender at least once before
        return {"sender": sender or "unknown number", "body": body[:3000], "minutes_ago": mins,
                "known": bool(replies)}
    return None


def sender_status(t):
    """One line for the model: has she ever written to this sender?"""
    if t.get("known"):
        return "KNOWN. She has written to this sender before."
    return "UNKNOWN. She has never written to this sender."


# ---------- background guard: new messages, and who is in Contacts ----------

def _chat(sql, args=()):
    con = sqlite3.connect("file:%s?mode=ro" % CHAT_DB, uri=True, timeout=3)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def _body(text, blob):
    body = (text or "").strip() or _decode_attributed_body(blob)
    return "" if body == "\ufffc" else body


def last_message_id():
    """ROWID of the newest message in Messages, or None if it cannot be read."""
    try:
        return _chat("SELECT MAX(ROWID) FROM message")[0][0] or 0
    except Exception as e:
        log("could not read Messages (grant Full Disk Access?):", e)
        return None


def incoming_since(rowid):
    """Incoming messages newer than `rowid`, oldest first: [{"id", "sender"}].
    Only who sent them. The content is fetched separately (message_body), and only
    after Contacts shows the sender is not saved."""
    try:
        rows = _chat(
            "SELECT m.ROWID, h.id FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "WHERE m.is_from_me = 0 AND m.ROWID > ? ORDER BY m.ROWID LIMIT 50", (rowid,))
    except Exception as e:
        log("could not read Messages:", e)
        return []
    return [{"id": rid, "sender": sender or ""} for rid, sender in rows]


def message_body(rowid):
    """The text of one message. Our own alerts come back empty."""
    try:
        rows = _chat("SELECT text, attributedBody FROM message WHERE ROWID = ?", (rowid,))
    except Exception as e:
        log("could not read Messages:", e)
        return ""
    body = _body(*rows[0]) if rows else ""
    if any(tag in body[:48] for tag in _OWN_ALERTS):
        return ""
    return body[:3000]


def thread_tail(sender, before_id, limit=6):
    """The last few messages exchanged with `sender` before message `before_id`,
    oldest first: [(from_me, body)]. Gives the model the conversation so far."""
    try:
        rows = _chat(
            "SELECT m.is_from_me, m.text, m.attributedBody "
            "FROM message m JOIN handle h ON m.handle_id = h.ROWID "
            "WHERE h.id = ? AND m.ROWID < ? ORDER BY m.ROWID DESC LIMIT ?",
            (sender, before_id, limit))
    except Exception:
        return []
    out = [(bool(me), _body(t, b)[:300]) for me, t, b in rows]
    return [x for x in reversed(out) if x[1]]


_contacts = (0, None)     # (time read, set of saved numbers / emails)


def _digits10(s):
    d = "".join(c for c in (s or "") if c.isdigit())
    return d[-10:] if len(d) >= 7 else ""


def saved_contacts():
    """Every phone number (last 10 digits) and email saved in Contacts, or None if
    Contacts cannot be read. Read-only, re-read at most every 20 seconds."""
    global _contacts
    if time.time() - _contacts[0] < 20:
        return _contacts[1]
    base = Path.home() / "Library" / "Application Support" / "AddressBook"
    found, ok = set(), False
    for db in [base / "AddressBook-v22.abcddb"] + sorted(base.glob("Sources/*/AddressBook-v22.abcddb")):
        if not db.exists():
            continue
        try:
            con = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=3)
            for (n,) in con.execute("SELECT ZFULLNUMBER FROM ZABCDPHONENUMBER"):
                if _digits10(n):
                    found.add(_digits10(n))
            for (a,) in con.execute("SELECT ZADDRESS FROM ZABCDEMAILADDRESS"):
                if a:
                    found.add(a.strip().lower())
            con.close()
            ok = True
        except Exception as e:
            log("could not read Contacts:", e)
    _contacts = (time.time(), found if ok else None)
    return _contacts[1]


def in_contacts(sender):
    """True / False, or None when Contacts cannot be read."""
    saved = saved_contacts()
    if saved is None:
        return None
    s = (sender or "").strip().lower()
    return (s in saved) if "@" in s else (_digits10(s) in saved)


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
    # Prefer clear, natural English voices (Enhanced/Premium first).
    for want in (
        "Zoe (Premium)", "Zoe (Enhanced)", "Zoe",
        "Nora (Premium)", "Nora (Enhanced)", "Nora",
        "Samantha (Premium)", "Samantha (Enhanced)", "Samantha",
        "Ava (Premium)", "Ava (Enhanced)", "Ava",
        "Allison (Premium)", "Allison (Enhanced)", "Allison",
    ):
        if want in names:
            pick = want
            break
    if not pick:
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
