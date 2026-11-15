"""The background guard. Nobody has to call it.

It watches Messages for new incoming texts. A sender saved in Contacts is left alone.
For every other sender it reads each new message quietly:
  - ordinary chat: it does nothing and says nothing, and keeps watching that number
    until the number is saved in Contacts;
  - risky content (prizes, bank or card details, SSN, codes, payments, odd links):
    it asks the model, and if the answer is SUSPICIOUS or SCAM it pops up, speaks,
    and messages the emergency contact on the account.
It only reads. It never replies to, deletes or opens anything."""
import threading
import time

import auth
import checker
import config
import mac
import voice
from mac import log
from pymongo.errors import PyMongoError

POLL_SECONDS = 3          # how often to look for new messages
QUIET_SECONDS = 300       # after alerting about a sender, stay quiet about them this long
MIN_GAP = 4               # seconds between model calls (the free tier is rate-limited)

_alerted = {}             # sender -> time of the last alert
_last_call = 0.0
_told_contacts = False


def _who(sender):
    """Sender for the log, without the full number."""
    return "…" + sender[-4:] if len(sender) > 4 else "unknown"


def is_risky(body):
    """Cheap local test: is there anything in this message worth a closer look?"""
    s = checker._risk_score(body)
    return bool(s.get("scam") or s.get("sus") or s.get("lottery") or s.get("payment")
                or s.get("impersonation") or s.get("link_trick"))


def _clearly_bad(body):
    """Used only when the model cannot be reached: strong signs on their own."""
    s = checker._risk_score(body)
    return bool(s.get("lottery") or s.get("payment") or s.get("scam", 0) >= 2)


def _local_verdict(sender):
    """A careful warning built without the model."""
    return {"verdict": "SUSPICIOUS", "item": "text", "sender": sender,
            "headline": "This message looks risky.",
            "reason": "It asks about money, prizes or private details.",
            "action": "Do not reply or share anything yet.",
            "speech": "A new message from an unknown number looks risky. "
                      "Do not reply or share anything yet.",
            "scene": "watch", "device": "mac", "local_rules": True}


def _alert(r):
    """Show and speak a warning without being asked."""
    import listener
    while listener._busy.locked():        # let a conversation in progress finish first
        time.sleep(0.3)
    with listener._busy:                  # and keep the wake word quiet while we speak
        if checker.ui_pop:
            checker.ui_pop()
        checker.show_result(r)
        if r["verdict"] == "SCAM":
            voice.chime()
        voice.speak(r["speech"])
        checker.idle_later(10)


def judge(m):
    """Look closely at one risky message from an unsaved number. Returns the result,
    or None if it turned out fine."""
    global _last_call
    sender, body = m["sender"], m["body"]
    wait = MIN_GAP - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()

    question = ("A new text just arrived from a number that is not saved in Contacts. "
                "Nobody asked about it yet. Is it safe?")
    tail = mac.thread_tail(sender, m["id"])
    if tail:
        question += " Conversation so far: " + " | ".join(
            ("Me: " if me else "Them: ") + b.replace('"', "'") for me, b in tail)
    text = ("From: %s\nSender status: UNKNOWN. This number is not saved in Contacts.\n"
            "Received: just now\n\n%s" % (sender, body))
    r = checker.run_check("mac", question, text=text, silent=True)

    if r.get("error"):
        if not _clearly_bad(body):
            log("guard: could not check a message from %s (model unavailable)" % _who(sender))
            return None
        r = _local_verdict(sender)
        doc = dict(r, question=question, has_image=False, text=text[:2000], email="",
                   created_at=checker.datetime.now(checker.timezone.utc))
        threading.Thread(target=checker._save, args=(doc,), daemon=True).start()
        if config.FAMILY_PHONE:
            mac.send_imessage(config.FAMILY_PHONE, checker.family_message(r))
    if r["verdict"] not in ("SCAM", "SUSPICIOUS"):
        log("guard: looked closer at a message from %s. It is fine." % _who(sender))
        return None
    log("guard: %s from %s | %s" % (r["verdict"], _who(sender), r["speech"]))
    _alerted[sender] = time.time()
    _alert(r)
    return r


def handle_message(m):
    """Check the sender first; fetch message content only for confirmed unknown senders."""
    global _told_contacts
    sender = m["sender"]
    if not sender or "id" not in m:
        return None
    known = mac.in_contacts(sender)
    if known is True:
        return None                       # saved in Contacts: not watched
    if known is None and not _told_contacts:
        _told_contacts = True
        log("guard paused: Contacts cannot be read, so unknown senders cannot be identified safely.")
    if known is None:
        return False                       # leave cursor here and retry when Contacts is readable
    body = mac.incoming_message_body(m["id"])
    if not body:
        return None
    m["body"] = body
    auth.record_unknown_message(m["id"], sender, body)
    if not is_risky(body):
        log("guard: ordinary message from unsaved number %s. Staying quiet." % _who(sender))
        return None
    if time.time() - _alerted.get(sender, 0) < QUIET_SECONDS:
        log("guard: already warned about %s a moment ago." % _who(sender))
        return None
    return judge(m)


def _loop():
    last = None
    while True:
        time.sleep(POLL_SECONDS)
        try:
            if not auth.current():
                last = None               # signed out: not watching
                continue
            if last is None:
                last = mac.last_message_id()   # start from now; never judge old history
                if last is None:
                    time.sleep(30)
                else:
                    log("guard: watching new messages from numbers not saved in Contacts.")
                continue
            for m in mac.incoming_senders_since(last):
                if handle_message(m) is False:
                    break
                last = m["id"]
        except auth.AuthError as e:
            log("guard paused:", str(e))
            time.sleep(30)
        except PyMongoError as e:
            log("guard database error:", type(e).__name__)
            time.sleep(10)
        except Exception as e:
            log("guard error:", e)
            time.sleep(5)


def start():
    if not config.WATCH_MESSAGES:
        log("guard: off (WATCH_MESSAGES=off)")
        return
    threading.Thread(target=_loop, daemon=True, name="hermes-guard").start()
