"""Sends the verification code by email.

Email goes out through Resend's HTTPS API (https://resend.com), because free hosting
blocks the ordinary mail ports. Needs RESEND_API_KEY, and EMAIL_FROM on a domain that
is verified in Resend. EMAIL_DEV_CODES=1 prints the code in the terminal instead
(for testing on your own machine only)."""
import requests

import config
from mac import log

_SUBJECT = {"signup": "is your %s code", "reset": "is your %s password reset code",
            "email": "is your %s code"}
_WHY = {"signup": "Enter this code to finish creating your account.",
        "reset": "Enter this code to choose a new password.",
        "email": "Enter this code to confirm your email address."}


class MailError(Exception):
    """The email could not be sent."""


def real_send_code(email, code, purpose):
    name = config.APP_NAME
    if config.EMAIL_DEV_CODES:
        log("EMAIL_DEV_CODES is on. Code for %s (%s): %s" % (email, purpose, code))
        return
    if not config.RESEND_API_KEY:
        log("email is not set up: add RESEND_API_KEY (or EMAIL_DEV_CODES=1 for local testing)")
        raise MailError("email is not set up")
    text = ("Your %s code is %s\n\n%s It is good for 10 minutes.\n\n"
            "%s will never ask you to share this code. If you did not ask for it, "
            "you can ignore this email." % (name, code, _WHY.get(purpose, _WHY["signup"]), name))
    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": "Bearer " + config.RESEND_API_KEY,
                     "Content-Type": "application/json"},
            json={"from": config.EMAIL_FROM, "to": [email],
                  "subject": "%s %s" % (code, _SUBJECT.get(purpose, _SUBJECT["signup"]) % name),
                  "text": text},
            timeout=15)
    except Exception as e:
        log("email failed:", str(e)[:120])
        raise MailError("could not reach the email service")
    if r.status_code >= 300:
        try:
            detail = str(r.json().get("message", ""))[:160]
        except Exception:
            detail = ""
        log("email failed: %s %s" % (r.status_code, detail))
        raise MailError("the email service refused the message")


# The rest of the app calls mailer.send_code; tests swap it for a recorder.
send_code = real_send_code
