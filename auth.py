"""Accounts: sign up with a phone number and date of birth, prove the phone with a
one-time code, set a password, sign in, reset a forgotten password.

Everything is stored on this Mac only, in data/accounts.json (never committed).
Passwords and codes are stored as salted hashes, never in plain text.
The code is delivered as an iMessage from this Mac, so it costs nothing."""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import date

import config
import mac
from mac import log

from pathlib import Path

DATA = Path(os.getenv("HERMES_DATA") or config.ROOT / "data")   # HERMES_DATA: tests only
FILE = DATA / "accounts.json"

CODE_MINUTES = 10        # how long a code stays valid
RESEND_SECONDS = 30      # wait this long before another code can be sent
CODE_TRIES = 5           # wrong codes allowed before a new one is needed
LOGIN_TRIES = 5          # wrong passwords allowed before a pause
LOGIN_PAUSE = 60         # seconds
MIN_PASSWORD = 8
YOUNG, OLD = 18, 50      # under 18 or over 50: an emergency contact is required

_lock = threading.RLock()
_pending = {}            # phone -> a sign-up or reset in progress (memory only)
_fails = {}              # phone -> (wrong password count, time of last one)


class AuthError(Exception):
    """A problem the person can fix. The message is shown on screen as written."""


# ---------- storage ----------

def _load():
    try:
        return json.loads(FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}, "signed_in": ""}


def _store(state):
    DATA.mkdir(exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)                 # readable by this Mac user only
    os.replace(tmp, FILE)


# ---------- small helpers ----------

def normalize_phone(raw):
    """'(214) 555-0123' -> '+12145550123'. Raises AuthError if it is not a phone number."""
    raw = (raw or "").strip()
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits[0] == "1":
        return "+" + digits
    raise AuthError("Please enter a 10-digit phone number.")


def mask(phone):
    digits = re.sub(r"\D", "", phone or "")
    return "(•••) •••-" + digits[-4:] if len(digits) >= 4 else "••••"


def age_on(dob, today=None):
    """Age in whole years for a 'YYYY-MM-DD' date of birth."""
    try:
        born = date.fromisoformat((dob or "").strip())
    except ValueError:
        raise AuthError("Please enter your date of birth.")
    today = today or date.today()
    years = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    if born > today or years > 120:
        raise AuthError("That date of birth does not look right.")
    return years


def needs_contact(dob):
    years = age_on(dob)
    return years < YOUNG or years > OLD


def _hash(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(salt), 200000).hex()


def _check_password(password):
    if len(password or "") < MIN_PASSWORD:
        raise AuthError("Use at least %d characters for your password." % MIN_PASSWORD)
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise AuthError("Use both letters and numbers in your password.")


def _public(user):
    """What the screen is allowed to know about the signed-in person."""
    return {"name": user["name"], "phone_masked": mask(user["phone"]),
            "age": age_on(user["dob"]), "needs_contact": needs_contact(user["dob"]),
            "contact_name": user.get("contact_name", ""),
            "contact_masked": mask(user["contact_phone"]) if user.get("contact_phone") else ""}


# ---------- one-time codes ----------

def _send_code(phone, entry):
    code = "%06d" % secrets.randbelow(1000000)
    salt = secrets.token_hex(16)
    entry.update(code_salt=salt, code_hash=_hash(code, salt), tries=0,
                 expires=time.time() + CODE_MINUTES * 60, sent_at=time.time(),
                 verified=False, ticket="")
    if config.AUTH_DEV_CODES:
        log("AUTH_DEV_CODES is on. Code for %s: %s" % (mask(phone), code))
        return
    msg = ("%s code: %s. It is good for %d minutes. %s will never ask you to share it."
           % (config.APP_NAME, code, CODE_MINUTES, config.APP_NAME))
    if not mac.send_imessage(phone, msg):
        raise AuthError("I could not send the code. Check that Messages is signed in on this Mac.")


def _code_reply(phone, entry):
    return {"phone": phone, "phone_masked": mask(phone), "resend_in": RESEND_SECONDS,
            "needs_contact": entry.get("needs_contact", False), "purpose": entry["purpose"]}


def start_signup(name, phone, dob):
    name = re.sub(r"\s+", " ", (name or "").strip())[:40]
    if not name:
        raise AuthError("Please enter your first name.")
    phone = normalize_phone(phone)
    must = needs_contact(dob)            # also checks the date
    with _lock:
        if phone in _load()["users"]:
            raise AuthError("This number already has an account. Please sign in.")
        entry = {"purpose": "signup", "name": name, "dob": dob.strip(), "needs_contact": must}
        _send_code(phone, entry)
        _pending[phone] = entry
        return _code_reply(phone, entry)


def start_reset(phone):
    phone = normalize_phone(phone)
    with _lock:
        if phone not in _load()["users"]:
            raise AuthError("I don't know this number yet. Please create an account.")
        entry = {"purpose": "reset"}
        _send_code(phone, entry)
        _pending[phone] = entry
        return _code_reply(phone, entry)


def resend(phone):
    phone = normalize_phone(phone)
    with _lock:
        entry = _pending.get(phone)
        if not entry:
            raise AuthError("Please start again.")
        wait = RESEND_SECONDS - (time.time() - entry.get("sent_at", 0))
        if wait > 0:
            raise AuthError("Please wait %d seconds, then ask for a new code." % (int(wait) + 1))
        _send_code(phone, entry)
        return _code_reply(phone, entry)


def verify_code(phone, code):
    """Returns a ticket that proves this phone was verified, for the next step."""
    phone = normalize_phone(phone)
    code = re.sub(r"\D", "", code or "")
    with _lock:
        entry = _pending.get(phone)
        if not entry or not entry.get("code_hash"):
            raise AuthError("Please start again.")
        if time.time() > entry["expires"]:
            raise AuthError("That code has expired. Ask for a new one.")
        if entry["tries"] >= CODE_TRIES:
            raise AuthError("Too many tries. Ask for a new code.")
        entry["tries"] += 1
        if not hmac.compare_digest(_hash(code, entry["code_salt"]), entry["code_hash"]):
            raise AuthError("That code is not right. Please check it and try again.")
        entry.update(verified=True, code_hash="", ticket=secrets.token_urlsafe(24),
                     ticket_until=time.time() + 15 * 60)
        return {"ticket": entry["ticket"], "purpose": entry["purpose"],
                "needs_contact": entry.get("needs_contact", False)}


def _ticketed(phone, ticket, purpose):
    entry = _pending.get(phone)
    if (not entry or entry["purpose"] != purpose or not entry.get("verified")
            or not ticket or not hmac.compare_digest(ticket, entry.get("ticket", ""))
            or time.time() > entry.get("ticket_until", 0)):
        raise AuthError("Please verify your phone again.")
    return entry


def _contact(own_phone, contact_name, contact_phone, required):
    contact_name = re.sub(r"\s+", " ", (contact_name or "").strip())[:40]
    if not (contact_phone or "").strip():
        if required:
            raise AuthError("An emergency contact is required for your age.")
        return "", ""
    phone = normalize_phone(contact_phone)
    if phone == own_phone:
        raise AuthError("The emergency contact must be someone else's number.")
    if not contact_name:
        raise AuthError("Please enter your emergency contact's name.")
    return contact_name, phone


# ---------- finishing sign-up, signing in, resetting ----------

def finish_signup(phone, ticket, password, contact_name="", contact_phone=""):
    phone = normalize_phone(phone)
    with _lock:
        entry = _ticketed(phone, ticket, "signup")
        _check_password(password)
        cname, cphone = _contact(phone, contact_name, contact_phone, entry["needs_contact"])
        salt = secrets.token_hex(16)
        state = _load()
        state["users"][phone] = {
            "name": entry["name"], "phone": phone, "dob": entry["dob"],
            "salt": salt, "password": _hash(password, salt),
            "contact_name": cname, "contact_phone": cphone, "created": int(time.time())}
        state["signed_in"] = phone
        _store(state)
        _pending.pop(phone, None)
    apply_to_config()
    return _public(state["users"][phone])


def reset_password(phone, ticket, password):
    phone = normalize_phone(phone)
    with _lock:
        _ticketed(phone, ticket, "reset")
        _check_password(password)
        state = _load()
        user = state["users"][phone]
        user["salt"] = secrets.token_hex(16)
        user["password"] = _hash(password, user["salt"])
        state["signed_in"] = phone
        _store(state)
        _pending.pop(phone, None)
        _fails.pop(phone, None)
    apply_to_config()
    return _public(user)


def login(phone, password):
    phone = normalize_phone(phone)
    with _lock:
        count, last = _fails.get(phone, (0, 0))
        if count >= LOGIN_TRIES and time.time() - last < LOGIN_PAUSE:
            raise AuthError("Too many tries. Please wait a minute, or tap Forgot password.")
        state = _load()
        user = state["users"].get(phone)
        # Same message for "no account" and "wrong password", so nobody can probe numbers.
        if not user or not hmac.compare_digest(_hash(password or "", user["salt"]), user["password"]):
            _fails[phone] = ((count if time.time() - last < LOGIN_PAUSE else 0) + 1, time.time())
            raise AuthError("That phone number or password is not right.")
        _fails.pop(phone, None)
        state["signed_in"] = phone
        _store(state)
    apply_to_config()
    return _public(user)


def logout():
    with _lock:
        state = _load()
        state["signed_in"] = ""
        _store(state)
    apply_to_config()


def set_contact(contact_name, contact_phone):
    """Change the emergency contact of the signed-in person."""
    with _lock:
        state = _load()
        user = state["users"].get(state.get("signed_in") or "")
        if not user:
            raise AuthError("Please sign in first.")
        user["contact_name"], user["contact_phone"] = _contact(
            user["phone"], contact_name, contact_phone, needs_contact(user["dob"]))
        _store(state)
    apply_to_config()
    return _public(user)


# ---------- who is signed in ----------

def current():
    """The signed-in account, or None."""
    state = _load()
    return state["users"].get(state.get("signed_in") or "")


def status():
    user = current()
    return {"signed_in": bool(user), "user": _public(user) if user else None,
            "has_accounts": bool(_load()["users"])}


def apply_to_config():
    """Point the rest of the app at the signed-in person: their name, and their
    emergency contact as the one who gets alerts. No contact means no alert is sent."""
    user = current()
    if user:
        config.GRANDMA_NAME = user["name"]
        config.FAMILY_PHONE = user.get("contact_phone", "")
        config.FAMILY_NAME = user.get("contact_name") or "there"
    else:
        config.GRANDMA_NAME, config.FAMILY_PHONE, config.FAMILY_NAME = _ENV_DEFAULTS


_ENV_DEFAULTS = (config.GRANDMA_NAME, config.FAMILY_PHONE, config.FAMILY_NAME)
