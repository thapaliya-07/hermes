"""MongoDB-backed accounts, consent records, and messages from unknown senders.

Passwords and one-time codes are stored as salted hashes. The code is delivered as
an iMessage from this Mac, so it costs nothing.
"""
import hashlib
import hmac
import re
import secrets
import threading
import time
from datetime import date, datetime, timedelta, timezone

import config
import mac
from mac import log
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError

CODE_MINUTES = 10        # how long a code stays valid
RESEND_SECONDS = 30      # wait this long before another code can be sent
CODE_TRIES = 5           # wrong codes allowed before a new one is needed
LOGIN_TRIES = 5          # wrong passwords allowed before a pause
LOGIN_PAUSE = 60         # seconds
MIN_PASSWORD = 8
MAX_PASSWORD = 18
YOUNG, OLD = 18, 50      # 18 or younger, or 50 or older: an emergency contact is required
RISK_CONSENT_VERSION = "2026-11-15-v2"
PRIVACY_CONSENT_VERSION = "2026-11-15-v2"
RISK_CONSENT_TEXT = (
    "I understand Hermes is a preventive aid, not a guarantee. It may miss scams or "
    "make mistakes, so I will verify important requests independently."
)
PRIVACY_CONSENT_TEXT = (
    "While you are signed in, the background watcher first checks whether an incoming "
    "sender is saved in Contacts without fetching the message content. The background "
    "watcher does not read or store message content from saved contacts, and pauses if "
    "Contacts cannot be checked. Content from senders not saved in "
    "Contacts is read and stored for 30 days. Information included in a scam check is "
    "also stored in MongoDB for 30 days. Suspicious content may be sent to Google "
    "Gemini for analysis."
)

_lock = threading.RLock()
_pending = {}            # phone -> a sign-up or reset in progress (memory only)
_fails = {}              # phone -> (wrong password count, time of last one)
_mongo = None
_database_cache = None
_indexes_ready = False
_session_loaded = False
_session_phone = ""
_session_user = None


class AuthError(Exception):
    """A problem the person can fix. The message is shown on screen as written."""


# ---------- storage ----------

def _database():
    global _mongo, _database_cache, _indexes_ready
    if not config.MONGODB_URI:
        raise AuthError("MongoDB is not configured. Add MONGODB_URI to .env and restart Hermes.")
    if _database_cache is None:
        client = MongoClient(config.MONGODB_URI, serverSelectionTimeoutMS=5000)
        try:
            client.admin.command("ping")
        except PyMongoError as e:
            client.close()
            log("MongoDB account connection failed:", type(e).__name__)
            raise AuthError(
                "Hermes could not connect to MongoDB. Check your network access and .env settings."
            ) from e
        _mongo = client
        _database_cache = client["trojan"]
    if not _indexes_ready:
        try:
            _database_cache["accounts"].create_index("phone", unique=True)
            messages = _database_cache["unknown_messages"]
            messages.create_index([("user_phone", 1), ("source_message_id", 1)], unique=True)
            messages.update_many(
                {"expires_at": {"$exists": False}},
                {"$set": {"expires_at": datetime.now(timezone.utc)
                          + timedelta(days=config.MESSAGE_RETENTION_DAYS)}})
            messages.create_index("expires_at", expireAfterSeconds=0)
            _indexes_ready = True
        except PyMongoError as e:
            log("MongoDB account indexes could not be initialized:", type(e).__name__)
            raise AuthError("Hermes could not prepare its MongoDB collections. Please try again.") from e
    return _database_cache


def _signed_in_user():
    global _session_loaded, _session_phone, _session_user
    if not _session_loaded:
        db = _database()
        state = db["app_state"].find_one({"_id": "active_session"}) or {}
        _session_phone = state.get("phone", "")
        _session_user = db["accounts"].find_one({"_id": _session_phone}) if _session_phone else None
        _session_loaded = True
    return _session_user


def _set_signed_in(user):
    global _session_loaded, _session_phone, _session_user
    phone = user.get("phone", "") if user else ""
    _database()["app_state"].update_one(
        {"_id": "active_session"}, {"$set": {"phone": phone}}, upsert=True)
    _session_phone, _session_user, _session_loaded = phone, user, True


def _consent_is_current(user):
    consent = user.get("consent", {})
    return bool(consent.get("risk_acknowledged")
                and consent.get("privacy_acknowledged")
                and consent.get("risk_version") == RISK_CONSENT_VERSION
                and consent.get("privacy_version") == PRIVACY_CONSENT_VERSION)


def _consent_record():
    accepted_at = datetime.now(timezone.utc)
    return {
        "risk_acknowledged": True,
        "privacy_acknowledged": True,
        "risk_version": RISK_CONSENT_VERSION,
        "privacy_version": PRIVACY_CONSENT_VERSION,
        "risk_text": RISK_CONSENT_TEXT,
        "privacy_text": PRIVACY_CONSENT_TEXT,
        "accepted_at": accepted_at,
    }


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
    if (not MIN_PASSWORD <= len(password or "") <= MAX_PASSWORD
            or not re.search(r"[A-Z]", password or "")
            or not re.search(r"[a-z]", password or "")
            or not re.search(r"\d", password or "")):
        raise AuthError(
            "Use 8–18 characters, including an uppercase letter, a lowercase letter, and a number."
        )


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
        if _database()["accounts"].find_one({"_id": phone}, {"_id": 1}):
            raise AuthError("This number already has an account. Please sign in.")
        entry = {"purpose": "signup", "first_name": first_name, "last_name": last_name,
                 "name": first_name + " " + last_name, "dob": dob.strip(), "needs_contact": must}
        _send_code(phone, entry)
        _pending[phone] = entry
        return _code_reply(phone, entry)


def start_reset(phone):
    phone = normalize_phone(phone)
    with _lock:
        if not _database()["accounts"].find_one({"_id": phone}, {"_id": 1}):
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
        consent = _consent_record()
        user = {
            "_id": phone, "first_name": entry["first_name"], "last_name": entry["last_name"],
            "name": entry["name"], "phone": phone, "dob": entry["dob"],
            "salt": salt, "password": _hash(password, salt),
            "contact_name": cname, "contact_phone": cphone, "created": int(time.time()),
            "consent": consent, "consent_history": [consent]}
        try:
            _database()["accounts"].insert_one(user)
        except DuplicateKeyError as e:
            raise AuthError("This number already has an account. Please sign in.") from e
        _set_signed_in(user)
        _pending.pop(phone, None)
    apply_to_config()
    return _public(user)


def reset_password(phone, ticket, password):
    phone = normalize_phone(phone)
    with _lock:
        _ticketed(phone, ticket, "reset")
        _check_password(password)
        user = _database()["accounts"].find_one({"_id": phone})
        if not user:
            raise AuthError("I don't know this number yet. Please create an account.")
        salt = secrets.token_hex(16)
        user["salt"], user["password"] = salt, _hash(password, salt)
        _database()["accounts"].update_one(
            {"_id": phone}, {"$set": {"salt": salt, "password": user["password"]}})
        _set_signed_in(user)
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
        user = _database()["accounts"].find_one({"_id": phone})
        # Same message for "no account" and "wrong password", so nobody can probe numbers.
        if not user or not hmac.compare_digest(_hash(password or "", user["salt"]), user["password"]):
            _fails[phone] = ((count if time.time() - last < LOGIN_PAUSE else 0) + 1, time.time())
            raise AuthError("That phone number or password is not right.")
        _fails.pop(phone, None)
        _set_signed_in(user)
    apply_to_config()
    return _public(user)


def logout():
    with _lock:
        _set_signed_in(None)
    apply_to_config()


def accept_consent(risk_consent, privacy_consent):
    if not risk_consent or not privacy_consent:
        raise AuthError("Please agree to both consent statements to continue.")
    with _lock:
        user = _signed_in_user()
        if not user:
            raise AuthError("Please sign in first.")
        was_current = _consent_is_current(user)
        consent = _consent_record()
        update = {"$set": {"consent": consent}}
        if not was_current:
            update["$push"] = {"consent_history": consent}
        _database()["accounts"].update_one({"_id": user["phone"]}, update)
        user["consent"] = consent
    apply_to_config()
    return _public(user)


def set_contact(contact_name, contact_phone):
    """Change the emergency contact of the signed-in person."""
    with _lock:
        user = current()
        if user is None:
            raise AuthError("Please sign in first.")
        cname, cphone = _contact(
            user["phone"], contact_name, contact_phone, needs_contact(user["dob"]))
        _database()["accounts"].update_one(
            {"_id": user["phone"]},
            {"$set": {"contact_name": cname, "contact_phone": cphone}})
        user["contact_name"], user["contact_phone"] = cname, cphone
        global _session_user
        _session_user.update(contact_name=cname, contact_phone=cphone)
    apply_to_config()
    return _public(user)


# ---------- who is signed in ----------

def current():
    """The signed-in account, or None."""
    with _lock:
        user = _signed_in_user()
        return user if user and _consent_is_current(user) else None


def status():
    with _lock:
        user = _signed_in_user()
        has_accounts = _database()["accounts"].count_documents({}, limit=1) > 0
    return {"signed_in": bool(user), "user": _public(user) if user else None,
            "consent_required": bool(user and not _consent_is_current(user)),
            "has_accounts": has_accounts}


def record_unknown_message(message_id, sender, body):
    """Persist one new message after Contacts confirms its sender is unknown."""
    user = current()
    if not user:
        raise AuthError("Consent is required before Hermes can process messages.")
    received_at = datetime.now(timezone.utc)
    result = _database()["unknown_messages"].update_one(
        {"user_phone": user["phone"], "source_message_id": message_id},
        {"$setOnInsert": {
            "user_phone": user["phone"],
            "source_message_id": message_id,
            "sender": sender,
            "body": body,
            "received_at": received_at,
            "expires_at": received_at + timedelta(days=config.MESSAGE_RETENTION_DAYS),
        }},
        upsert=True)
    if result.upserted_id:
        log("saved a new message from an unknown sender to MongoDB")


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
