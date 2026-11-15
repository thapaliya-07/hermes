"""Shared set-up for the tests. Nothing here touches the real database, sends a real
email, calls Gemini, or sends an iMessage."""
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Must be set before the app modules load: no database, no keys, a throwaway data folder.
os.environ["MONGODB_URI"] = ""
os.environ["GEMINI_API_KEY"] = "test-key-not-real"
os.environ["RESEND_API_KEY"] = ""
os.environ["EMAIL_DEV_CODES"] = ""
os.environ["WATCH_MESSAGES"] = "off"
os.environ["HERMES_DATA"] = tempfile.mkdtemp(prefix="hermes-tests-")

import auth      # noqa: E402
import config    # noqa: E402
import mac       # noqa: E402
import mailer    # noqa: E402

outbox = []      # every email the app tried to send: (to, code, purpose)
imessages = []   # every iMessage the app tried to send


def _fake_send_code(email, code, purpose):
    outbox.append((email, code, purpose))


mailer.send_code = _fake_send_code
mac.send_imessage = lambda phone, msg: imessages.append((phone, msg)) or True


def reset():
    """A clean slate: no accounts, nobody signed in, no pending codes."""
    data = Path(tempfile.mkdtemp(prefix="hermes-tests-"))
    auth.DATA, auth.FILE, auth.SESSION = data, data / "accounts.json", data / "session.json"
    auth._session = None
    auth._pending.clear()
    auth._fails.clear()
    auth._sends.clear()
    del outbox[:]
    del imessages[:]
    config.MONGODB_URI = ""


def last_code(email=None):
    for to, code, _ in reversed(outbox):
        if email is None or to == email:
            return code
    raise AssertionError("no code was emailed")


def wrong(code):
    return "000000" if code != "000000" else "111111"


def person(**changes):
    """A valid sign-up for a 76-year-old (so an emergency contact is required)."""
    p = dict(first_name="Ana", last_name="Diaz", phone="2145550100", email="ana@example.com",
             dob="1950-03-02", password="Passw0rdd", contact_name="Maya",
             contact_phone="2145550199", risk_consent=True, privacy_consent=True)
    p.update(changes)
    return p


def make_account(**changes):
    """Sign up and verify. Leaves the person signed in."""
    p = person(**changes)
    auth.start_signup(**p)
    auth.verify_signup(p["phone"], last_code(p["email"].lower()))
    return p


def born(years_ago):
    from datetime import date
    t = date.today()
    return date(t.year - years_ago, t.month, min(t.day, 28)).isoformat()
