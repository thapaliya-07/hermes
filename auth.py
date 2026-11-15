"""Accounts: sign up, prove the email address with a 6-digit code, sign in, and reset
a forgotten password with a code sent to that email.

Each account (names, phone, email, date of birth, password hash, emergency contact,
consent) is one document in the MongoDB "users" collection, so nothing about a person
is set in .env and the same account works from any device. Only "who is signed in on
this Mac" is kept locally, in data/session.json (never committed). Without MONGODB_URI
accounts fall back to a local file. Passwords and codes are stored as salted hashes.

Every rule is enforced here, on the server. The screens repeat some checks to be
helpful, but nothing depends on them."""
import contextvars
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import date
from pathlib import Path

import config
import mailer
from mac import log

DATA = Path(os.getenv("HERMES_DATA") or config.ROOT / "data")   # HERMES_DATA: tests only
FILE = DATA / "accounts.json"        # used only when there is no MONGODB_URI
SESSION = DATA / "session.json"

CODE_MINUTES = 10        # how long an emailed code stays valid
CODE_TRIES = 5           # wrong codes allowed before a new one is needed
RESEND_SECONDS = 30      # wait this long before another code can be sent
SENDS_PER_HOUR = 5       # codes one phone number may request in an hour
LOGIN_TRIES = 5          # wrong passwords allowed before a pause
LOGIN_PAUSE = 60         # seconds
MIN_PASSWORD, MAX_PASSWORD = 8, 18
YOUNG, OLD = 18, 50      # 18 or younger, or 50 or older: an emergency contact is required
# What the person agrees to on the consent screen. Changing a version asks everyone again.
RISK_CONSENT_VERSION = "2026-11-15-v3"
PRIVACY_CONSENT_VERSION = "2026-11-15-v3"
PASSWORD_RULE = ("Use 8–18 characters, including an uppercase letter, "
                 "a lowercase letter, and a number.")

_lock = threading.RLock()
_pending = {}            # phone -> a sign-up, reset or email change waiting for its code
_fails = {}              # phone -> (wrong password count, time of last one)
_sends = {}              # phone -> times codes were emailed (for the hourly limit)


class AuthError(Exception):
    """A problem the person can fix. The message is shown on screen as written;
    `field` says which input it is about (for example "password")."""

    def __init__(self, message, field=""):
        super().__init__(message)
        self.field = field


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
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)                 # readable by this computer's user only
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


# ---------- who is signed in ----------
# On the hosted server many people use the app at once, so "who is signed in" cannot be
# one file. There, each request carries its own session (see server.py): while a request
# is being handled, `_web` holds that browser's session and the functions below use it
# instead of the file on this Mac.
_web = contextvars.ContextVar("hermes_web_session", default=None)
_session = None


def user_fields(user):
    """The part of an account kept in a session: never the password hash."""
    keep = {k: user.get(k, "") for k in ("name", "first_name", "last_name", "phone", "email",
                                         "dob", "contact_name", "contact_phone")}
    keep["email_verified"] = bool(user.get("email_verified"))
    keep["consent"] = user.get("consent") or {}
    return keep


def _read_session():
    global _session
    web = _web.get()
    if web is not None:
        return {"user": web.get("user"), "seen": True}
    if _session is None:
        try:
            _session = json.loads(SESSION.read_text(encoding="utf-8"))
        except Exception:
            _session = {"user": None, "seen": False}
    return _session


def _sign_in(user):
    """Remember `user` as signed in (None signs out): for this browser on the hosted
    server, otherwise on this Mac."""
    global _session
    keep = user_fields(user) if user else None
    web = _web.get()
    if web is not None:
        web["user"], web["changed"] = keep, True
        return
    _session = {"user": keep, "seen": bool(user) or _read_session().get("seen", False)}
    _write(SESSION, _session)
    apply_to_config()


def signed_in():
    """Whoever is signed in, whether or not their account is fully set up."""
    return _read_session().get("user")


def _consent_ok(user):
    c = (user or {}).get("consent") or {}
    return (c.get("risk_version") == RISK_CONSENT_VERSION
            and c.get("privacy_version") == PRIVACY_CONSENT_VERSION)


def current():
    """The signed-in person, once their email is verified and they have agreed to the
    current consent statements. Until then nothing runs for them."""
    user = signed_in()
    return user if user and user.get("email_verified") and _consent_ok(user) else None


def status():
    user = signed_in()
    return {"signed_in": bool(user), "user": _public(user) if user else None,
            "email_required": bool(user and not user.get("email_verified")),
            "consent_required": bool(user and not _consent_ok(user)),
            "has_accounts": bool(_read_session().get("seen"))}


def get_account(phone):
    """Session fields for one account, or None (used by the hosted server)."""
    user = _get_user(phone)
    return user_fields(user) if user else None


def apply_to_config():
    """Point the Mac app at the signed-in person: their name, and their emergency contact
    as the one who gets alerts. No contact means no alert is sent."""
    user = current() or {}
    config.GRANDMA_NAME = user.get("name", "")
    config.FAMILY_PHONE = user.get("contact_phone", "")
    config.FAMILY_NAME = user.get("contact_name", "") or "there"
    config.USER_PHONE = user.get("phone", "")


# ---------- rules ----------

def normalize_phone(raw, field="phone"):
    """'(214) 555-0123' -> '+12145550123'."""
    raw = (raw or "").strip()
    digits = re.sub(r"\D", "", raw)
    if raw.startswith("+") and 8 <= len(digits) <= 15:
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits[0] == "1":
        return "+" + digits
    raise AuthError("Please enter a valid 10-digit phone number.", field)


_EMAIL = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)+$")


def normalize_email(raw):
    email = (raw or "").strip().lower()
    if not email or len(email) > 254 or ".." in email or not _EMAIL.match(email):
        raise AuthError("Please enter a valid email address.", "email")
    return email


def mask(phone):
    digits = re.sub(r"\D", "", phone or "")
    return "(•••) •••-" + digits[-4:] if len(digits) >= 4 else "••••"


def mask_email(email):
    name, _, domain = (email or "").partition("@")
    return (name[:1] + "•••@" + domain) if domain else ""


def age_on(dob, today=None):
    """Age in whole years for a 'YYYY-MM-DD' date of birth."""
    try:
        born = date.fromisoformat((dob or "").strip())
    except (ValueError, TypeError):
        raise AuthError("Please enter your date of birth.", "dob")
    today = today or date.today()
    years = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    if born > today or years > 120:
        raise AuthError("That date of birth does not look right.", "dob")
    return years


def needs_contact(dob):
    years = age_on(dob)
    return years <= YOUNG or years >= OLD


def check_password(password):
    password = password or ""
    if (not MIN_PASSWORD <= len(password) <= MAX_PASSWORD or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password) or not re.search(r"\d", password)):
        raise AuthError(PASSWORD_RULE, "password")


def _name(raw, what, field):
    name = re.sub(r"\s+", " ", (raw or "").strip())[:40]
    if not name:
        raise AuthError("Please enter %s." % what, field)
    return name


def _contact(own_phone, contact_name, contact_phone, required):
    if not (contact_phone or "").strip():
        if required:
            raise AuthError("An emergency contact is required for your age.", "contact_phone")
        return "", ""
    phone = normalize_phone(contact_phone, "contact_phone")
    if phone == own_phone:
        raise AuthError("The emergency contact must be someone else's number.", "contact_phone")
    return _name(contact_name, "your emergency contact's name", "contact_name"), phone


def _hash(secret, salt):
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(salt), 200000).hex()


def _consent_now():
    return {"risk_version": RISK_CONSENT_VERSION, "privacy_version": PRIVACY_CONSENT_VERSION,
            "accepted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _public(user):
    """What the screen is allowed to know about the signed-in person."""
    return {"name": user["name"], "phone_masked": mask(user["phone"]),
            "email_masked": mask_email(user.get("email", "")),
            "age": age_on(user["dob"]), "needs_contact": needs_contact(user["dob"]),
            "contact_name": user.get("contact_name", ""),
            "contact_masked": mask(user["contact_phone"]) if user.get("contact_phone") else ""}


# ---------- emailed codes ----------

def _send(phone, entry):
    """Email a fresh code for this pending step. Raises AuthError if it cannot."""
    now = time.time()
    recent = [t for t in _sends.get(phone, []) if now - t < 3600]
    if len(recent) >= SENDS_PER_HOUR:
        raise AuthError("Too many codes were requested. Please try again in an hour.", "code")
    code = "%06d" % secrets.randbelow(1000000)
    try:
        mailer.send_code(entry["email"], code, entry["purpose"])
    except mailer.MailError:
        raise AuthError("I could not send the email. Please check the address and try again.",
                        "email")
    salt = secrets.token_hex(16)
    entry.update(code_salt=salt, code_hash=_hash(code, salt), tries=0, sent_at=now,
                 expires=now + CODE_MINUTES * 60, verified=False, ticket="")
    _sends[phone] = recent + [now]


def _check_code(entry, purpose, code):
    """Raises unless `code` is the live code for this pending step. A code works once."""
    if not entry or entry.get("purpose") != purpose or not entry.get("code_hash"):
        raise AuthError("That code is not right. Please ask for a new one.", "code")
    if time.time() > entry["expires"]:
        raise AuthError("That code has expired. Ask for a new one.", "code")
    if entry["tries"] >= CODE_TRIES:
        raise AuthError("Too many wrong tries. Ask for a new code.", "code")
    entry["tries"] += 1
    code = re.sub(r"\D", "", code or "")
    if not hmac.compare_digest(_hash(code, entry["code_salt"]), entry["code_hash"]):
        raise AuthError("That code is not right. Please check it and try again.", "code")
    entry["code_hash"] = ""


def _sent(phone, entry, show_email=True):
    out = {"phone": phone, "purpose": entry["purpose"], "resend_in": RESEND_SECONDS}
    if show_email:
        out["email_masked"] = mask_email(entry["email"])
    return out


def resend(phone):
    phone = normalize_phone(phone)
    with _lock:
        entry = _pending.get(phone)
        if not entry or entry.get("verified"):
            raise AuthError("Please start again.", "code")
        wait = RESEND_SECONDS - (time.time() - entry.get("sent_at", 0))
        if wait > 0:
            raise AuthError("Please wait %d seconds, then ask for a new code." % (int(wait) + 1),
                            "code")
        _send(phone, entry)
        return _sent(phone, entry, show_email=entry["purpose"] != "reset")


# ---------- sign-up ----------

def start_signup(first_name="", last_name="", phone="", email="", dob="", password="",
                 contact_name="", contact_phone="", risk_consent=False, privacy_consent=False):
    """Check every detail, then email a code. The account is created only when the
    code comes back (verify_signup)."""
    first_name = _name(first_name, "your first name", "first_name")
    last_name = _name(last_name, "your last name", "last_name")
    phone = normalize_phone(phone)
    email = normalize_email(email)
    must = needs_contact(dob)            # also checks the date
    check_password(password)
    cname, cphone = _contact(phone, contact_name, contact_phone, must)
    if not risk_consent or not privacy_consent:
        raise AuthError("Please agree to both consent statements to continue.", "consent")
    with _lock:
        if _get_user(phone):
            raise AuthError("This number already has an account. Please sign in.", "phone")
        salt = secrets.token_hex(16)
        consent = _consent_now()
        user = {"name": first_name + " " + last_name, "first_name": first_name,
                "last_name": last_name, "phone": phone, "email": email, "email_verified": True,
                "dob": dob.strip(), "salt": salt, "password": _hash(password, salt),
                "contact_name": cname, "contact_phone": cphone, "created": int(time.time()),
                "consent": consent, "consent_history": [consent]}
        entry = {"purpose": "signup", "email": email, "user": user}
        _send(phone, entry)
        _pending[phone] = entry
        return _sent(phone, entry)


def verify_signup(phone, code):
    """The emailed code came back: create the account and sign in."""
    phone = normalize_phone(phone)
    with _lock:
        entry = _pending.get(phone)
        _check_code(entry, "signup", code)
        if _get_user(phone):
            raise AuthError("This number already has an account. Please sign in.", "phone")
        _put_user(entry["user"])
        _pending.pop(phone, None)
        _sign_in(entry["user"])
        return _public(entry["user"])


# ---------- signing in and out ----------

def login(phone, password):
    phone = normalize_phone(phone)
    with _lock:
        count, last = _fails.get(phone, (0, 0))
        if count >= LOGIN_TRIES and time.time() - last < LOGIN_PAUSE:
            raise AuthError("Too many tries. Please wait a minute, or tap Forgot password.",
                            "password")
        user = _get_user(phone)
        # Same message for "no account" and "wrong password", so nobody can probe numbers.
        if not user or not hmac.compare_digest(_hash(password or "", user["salt"]), user["password"]):
            _fails[phone] = ((count if time.time() - last < LOGIN_PAUSE else 0) + 1, time.time())
            raise AuthError("That phone number or password is not right.", "password")
        _fails.pop(phone, None)
        _sign_in(user)
    return _public(user)


def logout():
    with _lock:
        _sign_in(None)


# ---------- forgotten password ----------

def start_reset(phone):
    """Email a code to the address on the account. The reply is the same whether or not
    the number has an account, so nobody can use this to find out who is signed up."""
    phone = normalize_phone(phone)
    with _lock:
        user = _get_user(phone)
        entry = {"purpose": "reset", "email": (user or {}).get("email", "")}
        if user and user.get("email") and user.get("email_verified"):
            _send(phone, entry)
            _pending[phone] = entry
        else:
            _pending.pop(phone, None)
        return _sent(phone, entry, show_email=False)


def verify_reset(phone, code):
    """Returns a ticket that allows one password change."""
    phone = normalize_phone(phone)
    with _lock:
        entry = _pending.get(phone)
        _check_code(entry, "reset", code)
        entry.update(verified=True, ticket=secrets.token_urlsafe(24),
                     ticket_until=time.time() + 15 * 60)
        return {"phone": phone, "ticket": entry["ticket"]}


def reset_password(phone, ticket, password):
    """Change the password. This never signs anyone in: they sign in with the new one."""
    phone = normalize_phone(phone)
    with _lock:
        entry = _pending.get(phone)
        if (not entry or entry.get("purpose") != "reset" or not entry.get("verified")
                or not ticket or not hmac.compare_digest(str(ticket), entry.get("ticket") or "")
                or time.time() > entry.get("ticket_until", 0)):
            raise AuthError("Please ask for a new code and start again.", "code")
        check_password(password)
        user = _get_user(phone)
        if not user:
            raise AuthError("Please ask for a new code and start again.", "code")
        user["salt"] = secrets.token_hex(16)
        user["password"] = _hash(password, user["salt"])
        _put_user(user)
        _pending.pop(phone, None)
        _fails.pop(phone, None)
    return {}


# ---------- changes by the signed-in person ----------

def start_email(email):
    """An account made before email was required: add an address and prove it."""
    email = normalize_email(email)
    with _lock:
        me = signed_in()
        if not me:
            raise AuthError("Please sign in first.")
        entry = {"purpose": "email", "email": email}
        _send(me["phone"], entry)
        _pending[me["phone"]] = entry
        return _sent(me["phone"], entry)


def verify_email(code):
    with _lock:
        me = signed_in()
        if not me:
            raise AuthError("Please sign in first.")
        entry = _pending.get(me["phone"])
        _check_code(entry, "email", code)
        user = _get_user(me["phone"])
        if not user:
            raise AuthError("Please sign in first.")
        user["email"], user["email_verified"] = entry["email"], True
        _put_user(user)
        _pending.pop(me["phone"], None)
        _sign_in(user)
    return _public(user)


def accept_consent(risk_consent, privacy_consent):
    """Record that the signed-in person agreed to the current consent statements."""
    if not risk_consent or not privacy_consent:
        raise AuthError("Please agree to both consent statements to continue.", "consent")
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


# ---------- one entry point for the screens (used by app.py and server.py) ----------

def _s(d, key):
    v = d.get(key)
    return v if isinstance(v, str) else ""


STEPS = {
    "signup": lambda d: start_signup(
        _s(d, "first_name"), _s(d, "last_name"), _s(d, "phone"), _s(d, "email"), _s(d, "dob"),
        _s(d, "password"), _s(d, "contact_name"), _s(d, "contact_phone"),
        d.get("risk_consent") is True, d.get("privacy_consent") is True),
    "verify": lambda d: verify_signup(_s(d, "phone"), _s(d, "code")),
    "resend": lambda d: resend(_s(d, "phone")),
    "login": lambda d: login(_s(d, "phone"), _s(d, "password")),
    "logout": lambda d: logout(),
    "forgot": lambda d: start_reset(_s(d, "phone")),
    "forgot_verify": lambda d: verify_reset(_s(d, "phone"), _s(d, "code")),
    "reset": lambda d: reset_password(_s(d, "phone"), _s(d, "ticket"), _s(d, "password")),
    "email": lambda d: start_email(_s(d, "email")),
    "email_verify": lambda d: verify_email(_s(d, "code")),
    "consent": lambda d: accept_consent(d.get("risk_consent") is True,
                                        d.get("privacy_consent") is True),
    "contact": lambda d: set_contact(_s(d, "contact_name"), _s(d, "contact_phone")),
}


def run_step(step, data):
    """Run one account step. Returns what the screen should get back: always "ok",
    the new sign-in state on success, or the error and the field it is about."""
    try:
        out = STEPS[step](data if isinstance(data, dict) else {})
        return dict(out or {}, ok=True, state=status())
    except AuthError as e:
        return {"ok": False, "error": str(e), "field": e.field}


# ---------- one-time move of accounts made before the database was used ----------

def migrate_local():
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
