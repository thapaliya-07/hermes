"""Accounts: sign up with a phone number and date of birth, set a password, sign in,
reset a forgotten password (proved with the date of birth). No code is sent to the phone.

Each account (name, phone, date of birth, password hash, emergency contact) is one
document in the MongoDB "users" collection, so nothing about a person is hardcoded in
.env and the same account works from any Mac. Only "who is signed in on this Mac" is
kept locally, in data/session.json (never committed). Without MONGODB_URI the accounts
fall back to a local file. Passwords are stored as salted hashes."""
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
FILE = DATA / "accounts.json"        # used only when there is no MONGODB_URI
SESSION = DATA / "session.json"

LOGIN_TRIES = 5          # wrong passwords allowed before a pause
LOGIN_PAUSE = 60         # seconds
MIN_PASSWORD, MAX_PASSWORD = 8, 18
YOUNG, OLD = 18, 50      # 18 or younger, or 50 or older: an emergency contact is required
# What the person agrees to on the consent screen. Changing a version asks everyone again.
RISK_CONSENT_VERSION = "2026-11-15-v3"
PRIVACY_CONSENT_VERSION = "2026-11-15-v3"

_lock = threading.RLock()
_pending = {}            # phone -> a sign-up or reset in progress (memory only)
_fails = {}              # phone -> (wrong password count, time of last one)


class AuthError(Exception):
    """A problem the person can fix. The message is shown on screen as written."""


# ---------- storage ----------

def _users():
    """The MongoDB "users" collection, or None when MONGODB_URI is not set."""
    import checker
    col = checker.checks_collection()
    return None if col is None else col.database["users"]


def _local():
    try:
        return json.loads(FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}


def _write(path, obj):
    DATA.mkdir(exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)                 # readable by this Mac user only
    os.replace(tmp, path)


def _get_user(phone):
    """The account for this phone, or None."""
    col = _users()
    if col is None:
        return _local()["users"].get(phone)
    try:
        return col.find_one({"_id": phone}, {"_id": 0})
    except Exception as e:
        log("account database unreachable:", str(e)[:120])
        raise AuthError("I could not reach the account database. Check the internet and try again.")


def _put_user(user):
    col = _users()
    if col is None:
        state = _local()
        state["users"][user["phone"]] = user
        return _write(FILE, state)
    try:
        col.replace_one({"_id": user["phone"]}, dict(user, _id=user["phone"]), upsert=True)
    except Exception as e:
        log("account database unreachable:", str(e)[:120])
        raise AuthError("I could not reach the account database. Check the internet and try again.")


# Who is signed in on this Mac. A copy of their details is kept here so the background
# guard keeps working (and knows the emergency contact) even with no internet.
_session = None


def _read_session():
    global _session
    if _session is None:
        try:
            _session = json.loads(SESSION.read_text(encoding="utf-8"))
        except Exception:
            _session = {"user": None, "seen": False}
    return _session


def _sign_in(user):
    """Remember `user` as signed in on this Mac (None signs out)."""
    global _session
    keep = None
    if user:
        keep = {k: user.get(k, "") for k in ("name", "first_name", "last_name", "phone", "dob",
                                            "contact_name", "contact_phone")}
        keep["consent"] = user.get("consent") or {}
    _session = {"user": keep, "seen": bool(user) or _read_session().get("seen", False)}
    _write(SESSION, _session)
    apply_to_config()


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
    return years <= YOUNG or years >= OLD


def _hash(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(salt), 200000).hex()


def _check_password(password):
    password = password or ""
    if (not MIN_PASSWORD <= len(password) <= MAX_PASSWORD or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password) or not re.search(r"\d", password)):
        raise AuthError("Use 8–18 characters, including an uppercase letter, "
                        "a lowercase letter, and a number.")


def _consent_now():
    return {"risk_version": RISK_CONSENT_VERSION, "privacy_version": PRIVACY_CONSENT_VERSION,
            "accepted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _consent_ok(user):
    c = (user or {}).get("consent") or {}
    return (c.get("risk_version") == RISK_CONSENT_VERSION
            and c.get("privacy_version") == PRIVACY_CONSENT_VERSION)


def _public(user):
    """What the screen is allowed to know about the signed-in person."""
    return {"name": user["name"], "phone_masked": mask(user["phone"]),
            "age": age_on(user["dob"]), "needs_contact": needs_contact(user["dob"]),
            "contact_name": user.get("contact_name", ""),
            "contact_masked": mask(user["contact_phone"]) if user.get("contact_phone") else ""}


# ---------- starting sign-up or a password reset ----------
# There is no code sent to the phone. Each step hands back a short-lived ticket that the
# next step (choosing the password) must present.

def _ticket(phone, entry):
    entry.update(verified=True, ticket=secrets.token_urlsafe(24), ticket_until=time.time() + 15 * 60)
    _pending[phone] = entry
    return {"phone": phone, "ticket": entry["ticket"], "purpose": entry["purpose"],
            "needs_contact": entry.get("needs_contact", False)}


def start_signup(first_name, last_name, phone, dob):
    first_name = re.sub(r"\s+", " ", (first_name or "").strip())[:40]
    last_name = re.sub(r"\s+", " ", (last_name or "").strip())[:40]
    if not first_name:
        raise AuthError("Please enter your first name.")
    if not last_name:
        raise AuthError("Please enter your last name.")
    phone = normalize_phone(phone)
    must = needs_contact(dob)            # also checks the date
    with _lock:
        if _get_user(phone):
            raise AuthError("This number already has an account. Please sign in.")
        return _ticket(phone, {"purpose": "signup", "first_name": first_name, "last_name": last_name,
                               "name": first_name + " " + last_name, "dob": dob.strip(),
                               "needs_contact": must})


def start_reset(phone, dob):
    """Forgot password: the date of birth on the account is the proof of identity."""
    phone = normalize_phone(phone)
    age_on(dob)
    with _lock:
        count, last = _fails.get(phone, (0, 0))
        if count >= LOGIN_TRIES and time.time() - last < LOGIN_PAUSE:
            raise AuthError("Too many tries. Please wait a minute.")
        user = _get_user(phone)
        # Same message for "no account" and "wrong date", so nobody can probe numbers.
        if not user or not hmac.compare_digest(user["dob"], dob.strip()):
            _fails[phone] = ((count if time.time() - last < LOGIN_PAUSE else 0) + 1, time.time())
            raise AuthError("That phone number and date of birth do not match an account.")
        return _ticket(phone, {"purpose": "reset"})


def _ticketed(phone, ticket, purpose):
    entry = _pending.get(phone)
    if (not entry or entry["purpose"] != purpose or not entry.get("verified")
            or not ticket or not hmac.compare_digest(ticket, entry.get("ticket", ""))
            or time.time() > entry.get("ticket_until", 0)):
        raise AuthError("Please start again.")
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

def finish_signup(phone, ticket, password, contact_name="", contact_phone="",
                  risk_consent=False, privacy_consent=False):
    phone = normalize_phone(phone)
    with _lock:
        entry = _ticketed(phone, ticket, "signup")
        _check_password(password)
        if not risk_consent or not privacy_consent:
            raise AuthError("Please agree to both consent statements to continue.")
        cname, cphone = _contact(phone, contact_name, contact_phone, entry["needs_contact"])
        salt = secrets.token_hex(16)
        consent = _consent_now()
        user = {"name": entry["name"], "first_name": entry["first_name"],
                "last_name": entry["last_name"], "phone": phone, "dob": entry["dob"],
                "salt": salt, "password": _hash(password, salt),
                "contact_name": cname, "contact_phone": cphone, "created": int(time.time()),
                "consent": consent, "consent_history": [consent]}
        _put_user(user)
        _pending.pop(phone, None)
        _sign_in(user)
    return _public(user)


def reset_password(phone, ticket, password):
    phone = normalize_phone(phone)
    with _lock:
        _ticketed(phone, ticket, "reset")
        _check_password(password)
        user = _get_user(phone)
        if not user:
            raise AuthError("I don't know this number yet. Please create an account.")
        user["salt"] = secrets.token_hex(16)
        user["password"] = _hash(password, user["salt"])
        _put_user(user)
        _pending.pop(phone, None)
        _fails.pop(phone, None)
        _sign_in(user)
    return _public(user)


def login(phone, password):
    phone = normalize_phone(phone)
    with _lock:
        count, last = _fails.get(phone, (0, 0))
        if count >= LOGIN_TRIES and time.time() - last < LOGIN_PAUSE:
            raise AuthError("Too many tries. Please wait a minute, or tap Forgot password.")
        user = _get_user(phone)
        # Same message for "no account" and "wrong password", so nobody can probe numbers.
        if not user or not hmac.compare_digest(_hash(password or "", user["salt"]), user["password"]):
            _fails[phone] = ((count if time.time() - last < LOGIN_PAUSE else 0) + 1, time.time())
            raise AuthError("That phone number or password is not right.")
        _fails.pop(phone, None)
        _sign_in(user)
    return _public(user)


def logout():
    with _lock:
        _sign_in(None)


def accept_consent(risk_consent, privacy_consent):
    """Record that the signed-in person agreed to the current consent statements."""
    if not risk_consent or not privacy_consent:
        raise AuthError("Please agree to both consent statements to continue.")
    with _lock:
        me = signed_in()
        user = _get_user(me["phone"]) if me else None
        if not user:
            raise AuthError("Please sign in first.")
        if not _consent_ok(user):
            user["consent"] = _consent_now()
            user.setdefault("consent_history", []).append(user["consent"])
            _put_user(user)
        _sign_in(user)
    return _public(user)


def set_contact(contact_name, contact_phone):
    """Change the emergency contact of the signed-in person."""
    with _lock:
        me = signed_in()
        user = _get_user(me["phone"]) if me else None
        if not user:
            raise AuthError("Please sign in first.")
        user["contact_name"], user["contact_phone"] = _contact(
            user["phone"], contact_name, contact_phone, needs_contact(user["dob"]))
        _put_user(user)
        _sign_in(user)
    return _public(user)


def migrate_local():
    """One-time move: accounts created before the database was used are copied from
    the local file into MongoDB, and whoever was signed in stays signed in."""
    if _users() is None or not FILE.exists():
        return
    try:
        old = json.loads(FILE.read_text(encoding="utf-8"))
        moved = 0
        for phone, user in (old.get("users") or {}).items():
            if not _get_user(phone):
                _put_user(user)
                moved += 1
        who = (old.get("users") or {}).get(old.get("signed_in") or "")
        if who and not signed_in():
            _sign_in(who)
        os.replace(FILE, FILE.with_suffix(".json.migrated"))
        log("moved %d local account(s) into the database" % moved)
    except Exception as e:
        log("could not move local accounts into the database yet:", str(e)[:120])


# ---------- who is signed in ----------

def signed_in():
    """Whoever is signed in on this Mac, whether or not they have agreed to the consent."""
    return _read_session().get("user")


def current():
    """The signed-in person, once they have agreed to the current consent statements.
    Until then nothing runs for them: no guard, no wake word, no alerts."""
    user = signed_in()
    return user if user and _consent_ok(user) else None


def status():
    user = signed_in()
    return {"signed_in": bool(user), "user": _public(user) if user else None,
            "consent_required": bool(user and not _consent_ok(user)),
            "has_accounts": bool(_read_session().get("seen"))}


def apply_to_config():
    """Point the rest of the app at the signed-in person: their name, and their
    emergency contact as the one who gets alerts. No contact means no alert is sent."""
    user = current() or {}
    config.GRANDMA_NAME = user.get("name", "")
    config.FAMILY_PHONE = user.get("contact_phone", "")
    config.FAMILY_NAME = user.get("contact_name", "") or "there"
    config.USER_PHONE = user.get("phone", "")
