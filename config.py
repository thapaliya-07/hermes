"""All configuration in one place. Values come from .env (see .env.example)."""
import logging
import os
import warnings
from pathlib import Path

# Keep the terminal clean: hide library notices about the Python version etc.
warnings.filterwarnings("ignore")
logging.getLogger("google_genai").setLevel(logging.ERROR)
logging.getLogger("google_genai.types").setLevel(logging.ERROR)

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def _get(name, default=""):
    return (os.getenv(name) or default).strip()


GEMINI_API_KEY = _get("GEMINI_API_KEY")
GEMINI_MODEL = _get("GEMINI_MODEL", "gemini-flash-latest")
MONGODB_URI = _get("MONGODB_URI")
FAMILY_PHONE = _get("FAMILY_PHONE")
if FAMILY_PHONE.isdigit() and len(FAMILY_PHONE) == 10:
    FAMILY_PHONE = "+1" + FAMILY_PHONE  # bare US number -> +1XXXXXXXXXX
FAMILY_NAME = _get("FAMILY_NAME", "there")
GRANDMA_NAME = _get("GRANDMA_NAME", "Grandma")

# Trusted-contact verification (impersonation checks). Optional family phrase for emergencies.
# TRUSTED_CONTACTS: "Maya:+12145550123,Sam:+12145550199"  (comma-separated Name:phone)
VERIFY_PHRASE = _get("VERIFY_PHRASE")  # private family phrase; never spoken unprompted
SCAM_MEMORY_DAYS = int(_get("SCAM_MEMORY_DAYS", "14") or "14")
MESSAGE_RETENTION_DAYS = 30


def _parse_trusted_contacts(raw: str):
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            name, phone = part.split(":", 1)
        else:
            name, phone = FAMILY_NAME or "Family", part
        phone = phone.strip()
        if phone.isdigit() and len(phone) == 10:
            phone = "+1" + phone
        if phone:
            out.append({"name": name.strip() or "Family", "phone": phone,
                        "method": "imessage", "primary": False})
    return out


TRUSTED_CONTACTS = _parse_trusted_contacts(_get("TRUSTED_CONTACTS"))

# Voice
TROJAN_VOICE = _get("TROJAN_VOICE")  # empty = pick the best installed voice
TROJAN_RATE = _get("TROJAN_RATE", "165")
ELEVENLABS_API_KEY = _get("ELEVENLABS_API_KEY")
FISH_API_KEY = _get("FISH_API_KEY")
ELEVENLABS_VOICE_ID = _get("ELEVENLABS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")  # "Rachel": calm, clear
# Human-sounding voice from Gemini, using the same free GEMINI_API_KEY. "off" disables it.
GEMINI_VOICE = _get("GEMINI_VOICE", "Kore")   # clear/firm. Others: Aoede, Sulafat, Achernar
GEMINI_TTS_MODEL = _get("GEMINI_TTS_MODEL", "gemini-3.8-flash-lite-tts")
FISH_VOICE_ID = _get("FISH_VOICE_ID")  # empty = Fish default voice

# Accounts. AUTH_DEV_CODES=1 prints the one-time code in the terminal instead of
# sending it by iMessage (for testing only).
AUTH_DEV_CODES = _get("AUTH_DEV_CODES").lower() in ("1", "true", "yes", "on")
# Background guard: check new messages from numbers not saved in Contacts. "off" disables it.
WATCH_MESSAGES = _get("WATCH_MESSAGES", "on").lower() not in ("0", "off", "false", "no")

HOST = _get("HOST", "0.0.0.0")  # 0.0.0.0 so the iPhone Shortcut can reach the Mac
PORT = int(_get("PORT", "8000"))

# Product name: Hermes — Odyssey messenger who gave Odysseus moly against Circe's tricks.
APP_NAME = _get("APP_NAME", "Hermes")

# The name and the ways the free speech recognizer tends to mishear it.
_DEFAULT_WAKE = {
    "hermes": ("hermes,hermies,herman,hermie,her mes,her miss,ermis,armes,herms,"
               "hurmes,hermez,firms,her miss"),
    "moly": ("moly,molly,mollie,moley,moli,molli,molly's,mollys,mali,molle,holly,"
             "holy moly,holy molly,hey ma li"),
    "trojan": ("trojan,trojans,trogan,trojen,trojan's,trojin,trojon,troja,rojan,tojan,frozen,"
               "trogen,troy john,troy jan,tro john,true john"),
}
_wake = _get("WAKE_WORDS") or _DEFAULT_WAKE.get(APP_NAME.lower(), APP_NAME.lower())
_wake = [w.strip().lower() for w in _wake.split(",") if w.strip()]
WAKE_WORDS = tuple(w for w in _wake if " " not in w)      # single words
WAKE_PHRASES = tuple(w for w in _wake if " " in w)        # multi-word mishearings
