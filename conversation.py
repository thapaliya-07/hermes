"""Interactive voice conversation for Moly.

Instead of only wake → check → verdict, Moly can ask follow-ups, explain why
something is dangerous, call a trusted contact, and start verification.

Each session has an ID and a small rolling history. Only a short recent window
(plus a one-line summary) is sent to Gemini — never the entire chat log.
"""
import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import checker
import config
import mac
import memory
import verify
import voice
from mac import log

# ---------- sessions ----------

_sessions = {}
_lock = threading.Lock()
SESSION_TTL = 30 * 60  # 30 minutes of idle time
HISTORY_KEEP = 12      # stored locally
GEMINI_TURNS = 4       # max recent turns sent to the model


def _now():
    return time.time()


def _new_session() -> dict:
    return {
        "id": uuid.uuid4().hex[:12],
        "created_at": datetime.now(timezone.utc).isoformat() + "Z",
        "updated_at": _now(),
        "history": [],          # {role, text, ts}
        "summary": "",          # compact rolling summary for the model
        "last_check": None,     # last verdict dict
        "awaiting": None,       # e.g. "verify_confirm", "more_context"
        "incident_notes": [],   # short notes about prior incidents this session
    }


def get_session(session_id: Optional[str] = None) -> dict:
    with _lock:
        _expire()
        if session_id and session_id in _sessions:
            s = _sessions[session_id]
            s["updated_at"] = _now()
            return s
        s = _new_session()
        _sessions[s["id"]] = s
        return s


def _expire():
    cutoff = _now() - SESSION_TTL
    dead = [k for k, v in _sessions.items() if v.get("updated_at", 0) < cutoff]
    for k in dead:
        del _sessions[k]


def _remember(session: dict, role: str, text: str):
    session["history"].append({
        "role": role, "text": text, "ts": datetime.now(timezone.utc).isoformat() + "Z"})
    del session["history"][:-HISTORY_KEEP]
    session["updated_at"] = _now()


def recent_for_model(session: dict) -> list:
    """Small window only — never dump the full history into Gemini."""
    return session["history"][-GEMINI_TURNS:]


# ---------- intent (local, fast) ----------

_CALL = re.compile(
    r"\b(?:call|text|message|contact|reach|get)\b.*\b(?:daughter|son|family|"
    r"wife|husband|kids?|child|maya|unique|[a-z]{2,})\b|"
    r"\b(?:call|text|message)\s+my\b", re.I)
_VERIFY = re.compile(
    r"\b(?:verify|check with|ask (?:my |the )?family|is (?:this|it) real|"
    r"confirm|trusted contact)\b", re.I)
_WHY = re.compile(
    r"\b(?:why|what makes|how (?:do|did) you|explain|tell me more|"
    r"what(?:'s| is) (?:wrong|dangerous|suspicious))\b", re.I)
_CHECK = re.compile(
    r"\b(?:text|message|email|screen|safe|scam|suspicious|gift\s*card|"
    r"someone (?:called|texted|emailed)|grandson|money|clarify|"
    r"is this|look at|check)\b", re.I)
_YES = re.compile(r"^\s*(?:yes|yeah|yep|sure|please|ok|okay|do it)\b", re.I)
_NO = re.compile(r"^\s*(?:no|nope|nah|don'?t|do not|cancel|stop)\b", re.I)


def _strip_wake(utterance: str) -> str:
    """Remove 'Hey Hermes' / wake words so bare wake-ups don't force a check."""
    u = (utterance or "").strip()
    for w in config.WAKE_WORDS:
        u = re.sub(r"\bhey\s+" + re.escape(w) + r"\b", " ", u, flags=re.I)
        u = re.sub(r"\b" + re.escape(w) + r"\b", " ", u, flags=re.I)
    for p in config.WAKE_PHRASES:
        u = re.sub(re.escape(p), " ", u, flags=re.I)
    return re.sub(r"\s+", " ", u).strip(" .,!?:;")


def detect_intent(utterance: str, session: dict) -> str:
    u = (utterance or "").strip()
    core = _strip_wake(u)
    if not u or not core or core.lower() in ("hey", "hi", "hello", "there"):
        # Wake alone — greet and wait. Do NOT jump to a risk verdict.
        return "listen"
    awaiting = session.get("awaiting")
    if awaiting == "verify_confirm":
        if _YES.search(core) or _YES.search(u):
            return "verify_yes"
        if _NO.search(core) or _NO.search(u):
            return "verify_no"
    if _CALL.search(u) or _CALL.search(core):
        return "call_family"
    if _VERIFY.search(u) or _VERIFY.search(core):
        return "verify"
    if (_WHY.search(u) or _WHY.search(core)) and session.get("last_check"):
        return "why"
    # Only check when she asked to look / mentioned a message — never by default.
    if _CHECK.search(u) or _CHECK.search(core):
        return "check"
    if _WHY.search(u) or _WHY.search(core):
        return "why"
    return "chat"


def _contact_name_from(utterance: str) -> str:
    m = re.search(
        r"\b(?:my|the)\s+(daughter|son|family|wife|husband|kids?|child|"
        r"[A-Z][a-z]+)\b", utterance or "", re.I)
    return (m.group(1) if m else "").strip()


# ---------- dialogue helpers ----------

def _ask_gemini_chat(session: dict, user_text: str) -> str:
    """Short conversational reply with only recent turns + summary."""
    if not config.GEMINI_API_KEY:
        return ("I'm here. Tell me about the message, or ask me to check "
                "with your family.")
    try:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=config.GEMINI_API_KEY,
                             http_options=types.HttpOptions(timeout=10000))
        lines = []
        if session.get("summary"):
            lines.append("Session so far (summary): %s" % session["summary"])
        if session.get("last_check"):
            lc = session["last_check"]
            lines.append("Last verdict: %s — %s %s"
                         % (lc.get("verdict"), lc.get("headline"), lc.get("reason")))
        for turn in recent_for_model(session):
            who = "Grandma" if turn["role"] == "user" else config.APP_NAME
            lines.append("%s: %s" % (who, turn["text"]))
        lines.append("Grandma: %s" % user_text)
        prompt = (
            "You are %s, a calm scam guard for an elderly person. Continue the "
            "conversation in 1–3 short sentences (about 35 words). Warm, plain words, "
            "no jargon. You never click, reply, or send money for her. You may ask one "
            "follow-up if you need more detail (did they ask for money? gift cards?). "
            "If she wants family help, offer to contact a trusted person. "
            "Never treat a voice sounding familiar as proof of identity.\n\n%s\n\n"
            "Reply as %s only — the spoken words, nothing else."
            % (config.APP_NAME, "\n".join(lines), config.APP_NAME)
        )
        r = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.4))
        text = (r.text or "").strip().strip('"')
        _update_summary(session, user_text, text)
        return text or "I'm listening. Tell me a little more."
    except Exception as e:
        log("conversation chat failed:", e)
        return ("I'm listening. Tell me what the message says.")


def _update_summary(session: dict, user_text: str, reply: str):
    """Keep a tiny rolling summary so we don't resend the whole transcript."""
    bit = "She said %r. %s replied about that." % ((user_text or "")[:80], config.APP_NAME)
    prev = session.get("summary") or ""
    session["summary"] = (prev + " " + bit).strip()[-400:]


def _enrich_with_pattern(result: dict, body: str = "") -> dict:
    # A safe message never gets a "connected to an earlier suspicious message" warning.
    if result.get("verdict") == "SAFE" or result.get("error"):
        return result
    pattern = memory.remember_and_match(result, body=body)
    if not pattern:
        return result
    result["pattern"] = {
        "title": pattern["title"],
        "summary": pattern["summary"],
        "previous_headline": pattern["previous_headline"],
        "previous_when": pattern["previous_when"],
        "speech": pattern["speech"],
        "disclaimer": pattern["disclaimer"],
        "related_count": pattern["related_count"],
        "confidence": pattern["confidence"],
    }
    # Fold a short pattern note into speech (keep it speakable).
    extra = pattern["speech"]
    if extra and extra.lower() not in (result.get("speech") or "").lower():
        speech = (result.get("speech") or "").rstrip()
        if not speech.endswith("."):
            speech += "."
        # Keep total length reasonable for TTS
        combined = (speech + " " + extra).strip()
        if len(combined.split()) <= 22:
            result["speech"] = combined
        result["reason"] = (result.get("reason") or "") + " " + pattern["summary"]
        result["reason"] = result["reason"].strip()
    return result


def _maybe_offer_verify(session: dict, result: dict, body: str = "") -> dict:
    blob = " ".join(x for x in (body, result.get("reason"), result.get("speech"),
                                result.get("headline")) if x)
    if not verify.looks_like_impersonation(blob, result.get("verdict", ""), result.get("reason", "")):
        return result
    contact = verify.pick_contact()
    if not contact:
        return result
    offer = verify.offer_speech(contact)
    result["offer_verify"] = True
    result["verify_contact"] = contact.get("name")
    speech = (result.get("speech") or "").rstrip()
    if not speech.endswith("."):
        speech += "."
    result["speech"] = (speech + " " + offer).strip()
    session["awaiting"] = "verify_confirm"
    session["pending_verify_check"] = {
        "headline": result.get("headline"),
        "sender": result.get("sender"),
        "verdict": result.get("verdict"),
        "reason": result.get("reason"),
    }
    return result


def run_message_check(session: dict, question: str, speak: bool = True,
                      before_speaking=None) -> dict:
    """Look at the message first, then judge — never assume suspicious up front."""
    # Step 1: show/speak that we are looking (not judging yet).
    checker.publish("thinking", device="mac", headline="Looking at the message.",
                    reason="", action="", scene="harbor", session_id=session.get("id"))

    # Use the screenshot taken at the moment of waking (our window was not on screen yet).
    taken, shot = checker.wake_shot
    checker.wake_shot = (0, None)
    if not shot or time.time() - taken > 20:
        if checker.ui_hide:
            checker.ui_hide()
        shot = mac.screenshot()
    if checker.ui_pop:
        checker.ui_pop()
    t = mac.latest_text()
    text = None
    body_for_memory = ""
    if t:
        text = "From: %s\nSender status: %s\nReceived: %d minutes ago\n\n%s" % (
            t["sender"], mac.sender_status(t), t["minutes_ago"], t["body"])
        body_for_memory = t["body"]
    # Judge what she asked about. "My screen / this / notification" means the screenshot,
    # not whichever text happened to arrive last.
    q = (question or "").lower()
    names_text = bool(re.search(r"\b(text|texts|message|messages|messi|sms|imessage)\b", q))
    names_screen = bool(re.search(r"\b(screen|display|notification|pop-?up|window|page|website|"
                                  r"this|look at|looking at|read)\b", q))
    if shot:
        if names_screen and not names_text:
            text = None                              # screen only
        elif text and not names_text and t and t["minutes_ago"] > 30:
            # an old text she did not mention is not what is in front of her
            text = None
    log("conversation check: text=%s shot=%s" % (bool(text), bool(shot)))

    # Step 2: if nothing to read, ask calmly — do not talk about scams yet.
    if not (text or shot) and not _has_enough_story(question):
        reply = ("I don't see a message yet. Open the text, then ask me to check it.")
        session["awaiting"] = "more_context"
        return {"verdict": "SAFE", "speech": reply, "headline": "Looking for a message.",
                "reason": "Nothing to read yet.", "action": "Open the text and ask again.",
                "item": "screen", "sender": "unknown", "scene": "harbor",
                "conversational": True}

    # Step 3: only now filter safe / suspicious / scam from the content.
    neutral_q = question or "Please look at this message and tell me what you find."
    if re.search(r"\bis this safe\b", neutral_q, re.I):
        neutral_q = ("Look at the latest text or what is on screen first. Judge only from "
                     "its words. Do not assume it is suspicious.")
    r = checker.run_check("mac", neutral_q, text=text, email=None, image_bytes=shot,
                          skip_memory=True)  # we handle memory here
    if r.get("item") == "screen" or not text:
        body_for_memory = ""
    elif t:
        body_for_memory = t.get("body", body_for_memory)

    r = _enrich_with_pattern(r, body=body_for_memory)
    r = _maybe_offer_verify(session, r, body=body_for_memory)
    session["last_check"] = {k: r.get(k) for k in
                             ("verdict", "headline", "reason", "action", "speech",
                              "item", "sender", "pattern", "offer_verify")}
    if r.get("pattern"):
        session["incident_notes"].append(r["pattern"].get("summary", ""))
        del session["incident_notes"][:-6]

    # Persist pattern onto the saved check document asynchronously via checker hook
    if r.get("pattern"):
        checker.attach_pattern_to_latest(r["pattern"])

    if before_speaking:
        before_speaking()
    # Speaking / FaceTime / idle are owned by turn() when speak=False (normal path).
    if speak:
        if r.get("verdict") == "SCAM" and not r.get("error"):
            voice.chime()
        voice.speak(r["speech"])
        if r.get("verdict") == "SCAM" and not r.get("error") and not r.get("offer_verify"):
            mac.open_facetime(config.FAMILY_PHONE)
        checker.idle_later(8)
    elif r.get("verdict") == "SCAM" and not r.get("error") and not r.get("offer_verify"):
        mac.open_facetime(config.FAMILY_PHONE)
    return r


def _has_enough_story(question: str) -> bool:
    q = (question or "").lower()
    return bool(re.search(r"\b(?:gift\s*card|money|grandson|jail|arrest|amazon|bank|code)\b", q))


def _do_verify(session: dict, utterance: str = "") -> dict:
    check = session.get("pending_verify_check") or session.get("last_check") or {
        "headline": "Possible impersonation",
        "sender": "unknown",
        "verdict": "SCAM",
        "reason": "Someone may be pretending to be family.",
    }
    contact = verify.pick_contact(_contact_name_from(utterance))
    started = verify.start_verification(check, contact=contact,
                                        use_phrase=bool(config.VERIFY_PHRASE))
    session["awaiting"] = None
    if not started:
        speech = ("I couldn't reach a trusted contact just now. "
                  "Please call someone you trust yourself before sending anything.")
        return {"speech": speech, "verdict": check.get("verdict", "SUSPICIOUS"),
                "headline": "Could not verify.", "verification": None}
    session["active_verification_id"] = started["id"]
    return {
        "speech": started["speech"],
        "verdict": check.get("verdict", "SUSPICIOUS"),
        "headline": "Checking with %s." % started["contact_name"],
        "verification": started,
    }


def _do_call_family(utterance: str) -> dict:
    contact = verify.pick_contact(_contact_name_from(utterance))
    if not contact:
        speech = "I don't have a family number saved. Please call someone you trust."
        return {"speech": speech, "verdict": "SUSPICIOUS", "headline": "No contact saved."}
    mac.open_facetime(contact["phone"])
    # Also ping them so they know why
    mac.send_imessage(
        contact["phone"],
        "%s here. %s asked me to call you. She may need your help with a message."
        % (config.APP_NAME, config.GRANDMA_NAME))
    speech = "Okay. I'm calling %s for you now." % contact.get("name", "your family")
    return {"speech": speech, "verdict": "SUSPICIOUS", "headline": "Calling %s." % contact.get("name", "family"),
            "contact": contact.get("name")}


def _explain_why(session: dict) -> dict:
    lc = session.get("last_check") or {}
    bits = [lc.get("reason"), lc.get("action")]
    if lc.get("pattern"):
        bits.append(lc["pattern"].get("summary"))
    bits = [b for b in bits if b]
    if not bits:
        speech = ("I look for rush, money requests, odd web addresses, and people "
                  "pretending to be family. When those show up together, I warn you.")
    else:
        speech = " ".join(bits)
        if lc.get("offer_verify"):
            speech += " We can also check with your family before you do anything."
    # Keep speakable
    words = speech.split()
    if len(words) > 45:
        speech = " ".join(words[:45]).rstrip(",;") + "."
    return {
        "speech": speech,
        "verdict": lc.get("verdict", "SUSPICIOUS"),
        "headline": lc.get("headline") or "Here's why.",
        "reason": lc.get("reason", ""),
        "action": lc.get("action", ""),
    }


# ---------- public turn API ----------

def turn(utterance: str, session_id: Optional[str] = None, speak: bool = True,
         before_speaking=None, force_check: bool = False) -> dict:
    """Handle one conversational turn. Returns a response dict including session_id."""
    session = get_session(session_id)
    utterance = (utterance or "").strip()
    _remember(session, "user", utterance)
    intent = "check" if force_check else detect_intent(utterance, session)
    log("conversation %s intent=%s: %s" % (session["id"], intent, utterance[:80]))

    checker.publish("thinking", device="mac", session_id=session["id"])

    if intent == "verify_yes" or (intent == "verify" and session.get("last_check")):
        result = _do_verify(session, utterance)
    elif intent == "verify_no":
        session["awaiting"] = None
        result = {
            "speech": "Okay. We won't check with them. Please don't send money or codes.",
            "verdict": (session.get("last_check") or {}).get("verdict", "SUSPICIOUS"),
            "headline": "Okay, skipping that.",
        }
    elif intent == "verify":
        # No prior check — still offer to verify after we look
        result = run_message_check(session, utterance, speak=False,
                                   before_speaking=before_speaking)
        if not result.get("offer_verify"):
            # Start verification on whatever we found if she explicitly asked
            result = _do_verify(session, utterance)
    elif intent == "call_family":
        result = _do_call_family(utterance)
    elif intent == "why":
        result = _explain_why(session)
    elif intent == "listen":
        result = {
            "speech": "I'm here. Show me the message, or say check this.",
            "verdict": "SAFE",
            "headline": "I'm here.",
            "reason": "",
            "action": "Ask me to check the message.",
            "item": "screen",
            "sender": "unknown",
            "scene": "harbor",
            "conversational": True,
        }
    elif intent == "check" or force_check:
        result = run_message_check(session, utterance, speak=False,
                                   before_speaking=before_speaking)
    else:
        # She may still be describing a scam in plain words — check when the story is rich enough.
        if _CHECK.search(utterance) and _has_enough_story(utterance):
            result = run_message_check(session, utterance, speak=False,
                                       before_speaking=before_speaking)
        else:
            reply = _ask_gemini_chat(session, utterance)
            result = {
                "speech": reply,
                "verdict": "SAFE",
                "headline": "I'm listening.",
                "reason": "",
                "action": "",
                "item": "screen",
                "sender": "unknown",
                "scene": "harbor",
                "conversational": True,
            }

    speech = result.get("speech") or "I'm here."
    _remember(session, "assistant", speech)
    result["session_id"] = session["id"]
    result["intent"] = intent
    result["awaiting"] = session.get("awaiting")

    state = (result.get("verdict") or "suspicious").lower()
    if result.get("conversational") and state == "safe":
        state = "listening"
    if state not in ("safe", "suspicious", "scam", "listening", "thinking"):
        state = "suspicious"
    checker.publish(state, device="mac", headline=result.get("headline"),
                    reason=result.get("reason"), action=result.get("action"),
                    sender=result.get("sender"), item=result.get("item"),
                    scene=result.get("scene", "harbor"),
                    session_id=session["id"],
                    pattern=result.get("pattern"),
                    offer_verify=result.get("offer_verify"))

    if before_speaking and intent not in ("check", "verify"):
        before_speaking()
    if speak:
        if (result.get("verdict") == "SCAM" and not result.get("error")
                and not result.get("conversational")):
            voice.chime()
        voice.speak(speech)

    checker.idle_later(10)
    return result
