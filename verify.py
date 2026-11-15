"""Trusted contact verification for possible impersonation attempts.

When Moly suspects someone is pretending to be family ("I'm your grandson…"),
it can ask Grandma whether to verify with a pre-approved contact over a known
channel (iMessage). The trusted person confirms or denies. An optional family
verification phrase can be used during emergencies.

Voice match / AI-generated voice detection is never treated as definitive
identity proof — those methods can fail.
"""
import re
import secrets
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

import config
import mac
from mac import log

# In-memory pending requests (also mirrored to Mongo when available).
_pending = {}  # id -> dict
_lock = threading.Lock()
_mongo = None

# Impersonation / emergency-money cues (plain-language matching).
_IMPERSONATION = re.compile(
    r"\b(?:i(?:'m| am) your|this is your|grandson|granddaughter|nephew|niece|"
    r"in (?:trouble|jail|hospital)|arrested|car (?:accident|crash)|"
    r"lost my phone|new phone|can(?:'?t|not) talk|don(?:'?t|ot) tell|"
    r"need (?:money|cash|gift)|send (?:me )?(?:money|\$)|wire|bail|"
    r"amazon|apple|microsoft|irs|social security)\b", re.I)


def looks_like_impersonation(text: str = "", verdict: str = "", reason: str = "") -> bool:
    blob = " ".join(x for x in (text, reason) if x)
    if not blob:
        return False
    if verdict == "SCAM" and _IMPERSONATION.search(blob):
        return True
    if verdict in ("SCAM", "SUSPICIOUS") and _IMPERSONATION.search(blob):
        # money + family / authority cues together
        money = re.search(r"\b(?:money|gift\s*card|wire|bail|\$\d+)\b", blob, re.I)
        return bool(money or verdict == "SCAM")
    return bool(_IMPERSONATION.search(blob) and re.search(r"\b(?:money|gift|send|pay)\b", blob, re.I))


def trusted_contacts() -> list:
    """Pre-approved family contacts. Always includes FAMILY_PHONE when set."""
    contacts = list(config.TRUSTED_CONTACTS)
    if config.FAMILY_PHONE:
        primary = {"name": config.FAMILY_NAME or "Family", "phone": config.FAMILY_PHONE,
                   "method": "imessage", "primary": True}
        if not any(c.get("phone") == config.FAMILY_PHONE for c in contacts):
            contacts.insert(0, primary)
    return contacts


def pick_contact(name_hint: str = "") -> Optional[dict]:
    contacts = trusted_contacts()
    if not contacts:
        return None
    if name_hint:
        hint = name_hint.lower().strip()
        for c in contacts:
            if hint in (c.get("name") or "").lower() or (c.get("name") or "").lower() in hint:
                return c
    for c in contacts:
        if c.get("primary"):
            return c
    return contacts[0]


def _collection():
    global _mongo
    if not config.MONGODB_URI:
        return None
    if _mongo is None:
        from pymongo import MongoClient
        _mongo = MongoClient(config.MONGODB_URI, serverSelectionTimeoutMS=5000)
    return _mongo["trojan"]["verifications"]


def _persist(doc: dict):
    col = _collection()
    if col is None:
        return
    try:
        col.update_one({"id": doc["id"]}, {"$set": doc}, upsert=True)
    except Exception as e:
        log("verify persist failed:", e)


def _load(vid: str) -> Optional[dict]:
    with _lock:
        if vid in _pending:
            return dict(_pending[vid])
    col = _collection()
    if col is None:
        return None
    try:
        doc = col.find_one({"id": vid}, {"_id": 0})
        if doc:
            with _lock:
                _pending[vid] = doc
            return dict(doc)
    except Exception as e:
        log("verify load failed:", e)
    return None


def offer_speech(contact: Optional[dict] = None) -> str:
    who = (contact or pick_contact() or {}).get("name") or "your family"
    return ("Would you like me to check with %s first? "
            "I can contact them the usual way and ask if this is real." % who)


def start_verification(check: dict, contact: Optional[dict] = None,
                       use_phrase: bool = False) -> Optional[dict]:
    """Message a trusted contact and wait for their confirm/deny.

    Does not use voice matching. Identity proof is the known contact channel
    (and optionally the family verification phrase).
    """
    contact = contact or pick_contact()
    if not contact or not contact.get("phone"):
        log("no trusted contact available for verification")
        return None
    vid = uuid.uuid4().hex[:10]
    code = secrets.token_hex(2).upper()  # short reply code, e.g. A1B2
    doc = {
        "id": vid,
        "code": code,
        "status": "pending",  # pending | confirmed | denied | expired
        "contact_name": contact.get("name", "Family"),
        "contact_phone": contact["phone"],
        "method": contact.get("method", "imessage"),
        "check_headline": check.get("headline", ""),
        "check_sender": check.get("sender", "unknown"),
        "check_verdict": check.get("verdict", ""),
        "check_reason": check.get("reason", ""),
        "grandma": config.GRANDMA_NAME,
        "use_phrase": bool(use_phrase and config.VERIFY_PHRASE),
        "created_at": datetime.now(timezone.utc).isoformat() + "Z",
        "resolved_at": None,
        "note": "",
        # Explicit product rule: never treat voice biometrics as proof.
        "voice_match_is_not_proof": True,
    }
    with _lock:
        _pending[vid] = doc
    _persist(doc)

    app, who = config.APP_NAME, config.GRANDMA_NAME
    phrase_line = ""
    if doc["use_phrase"]:
        phrase_line = (" If this is a real emergency, include your family "
                       "verification phrase in the reply.")
    msg = (
        "%s verification request. %s got a message that may be someone "
        "pretending to be family (from %s). Headline: %s. "
        "Reply YES %s if this is legitimate, or NO %s if it is not.%s "
        "Do not rely on a voice sounding familiar — please confirm yourself."
        % (app, who, doc["check_sender"], doc["check_headline"] or "possible impersonation",
           code, code, phrase_line)
    )
    ok = mac.send_imessage(contact["phone"], msg)
    doc["notified"] = bool(ok)
    _persist(doc)
    log("verification %s started with %s (code %s)" % (vid, contact.get("name"), code))
    return {
        "id": vid,
        "status": "pending",
        "contact_name": doc["contact_name"],
        "speech": ("Okay. I've asked %s to confirm whether this is real. "
                   "Please wait for their answer before sending anything."
                   % doc["contact_name"]),
        "voice_match_is_not_proof": True,
    }


def respond(vid: str = "", code: str = "", decision: str = "",
            note: str = "", phrase: str = "") -> Optional[dict]:
    """Family confirms or denies. decision: yes/confirmed or no/denied."""
    doc = None
    if vid:
        doc = _load(vid)
    if doc is None and code:
        with _lock:
            for d in _pending.values():
                if d.get("code", "").upper() == code.upper():
                    doc = dict(d)
                    break
        if doc is None:
            col = _collection()
            if col is not None:
                try:
                    found = col.find_one({"code": code.upper(), "status": "pending"}, {"_id": 0})
                    if found:
                        doc = found
                except Exception:
                    pass
    if not doc:
        return None

    decision_l = (decision or "").strip().lower()
    if decision_l in ("yes", "y", "confirm", "confirmed", "legitimate", "real"):
        status = "confirmed"
    elif decision_l in ("no", "n", "deny", "denied", "scam", "fake"):
        status = "denied"
    else:
        return None

    # Optional phrase check: if the request asked for it and a phrase is configured,
    # require a match to confirm (denials still go through without it).
    if status == "confirmed" and doc.get("use_phrase") and config.VERIFY_PHRASE:
        expected = config.VERIFY_PHRASE.strip().lower()
        given = (phrase or note or "").strip().lower()
        if expected not in given and given != expected:
            return {
                "id": doc["id"],
                "status": "pending",
                "error": "verification_phrase_required",
                "speech": "Please include the family verification phrase to confirm.",
            }

    doc["status"] = status
    doc["note"] = (note or "")[:300]
    doc["resolved_at"] = datetime.now(timezone.utc).isoformat() + "Z"
    with _lock:
        _pending[doc["id"]] = doc
    _persist(doc)

    if status == "confirmed":
        speech = ("I heard back from %s. They say this request looks legitimate. "
                  "Still, only send money if you are sure."
                  % doc["contact_name"])
        grandma_msg = ("%s update. %s confirmed that message looked legitimate. "
                       "Please still be careful."
                       % (config.APP_NAME, doc["contact_name"]))
    else:
        speech = ("I heard back from %s. They say this is not real. "
                  "Please do not send money or share codes."
                  % doc["contact_name"])
        grandma_msg = ("%s update. %s said that message is NOT legitimate. "
                       "Do not send money or gift cards."
                       % (config.APP_NAME, doc["contact_name"]))

    # Tell Grandma via the same family phone channel if we can (primary contact
    # already knows; for multi-contact setups the dashboard/API is the source of truth).
    result = {
        "id": doc["id"],
        "status": status,
        "contact_name": doc["contact_name"],
        "speech": speech,
        "grandma_message": grandma_msg,
        "voice_match_is_not_proof": True,
    }
    return result


def explain_result(result: dict) -> str:
    return result.get("speech") or "I could not finish the verification."


def pending_list(limit: int = 20) -> list:
    with _lock:
        rows = [dict(v) for v in _pending.values() if v.get("status") == "pending"]
    rows.sort(key=lambda d: d.get("created_at", ""), reverse=True)
    if rows:
        return rows[:limit]
    col = _collection()
    if col is None:
        return []
    try:
        return list(col.find({"status": "pending"}, {"_id": 0})
                    .sort("created_at", -1).limit(limit))
    except Exception:
        return []


def get_verification(vid: str) -> Optional[dict]:
    return _load(vid)
