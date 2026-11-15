"""Scam Memory: remember suspicious incidents across days and spot patterns.

Scammers often warm up over several messages. Individually each one can look mild;
together they form a pattern. This module stores prior incidents, normalizes
senders/domains, and compares new checks against recent memory.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import config
from mac import log

# ---------- Mongo ----------

_mongo = None
_indexes_ok = False


def _db():
    global _mongo
    if not config.MONGODB_URI:
        return None
    if _mongo is None:
        from pymongo import MongoClient
        _mongo = MongoClient(config.MONGODB_URI, serverSelectionTimeoutMS=5000)
    return _mongo["trojan"]


def memory_collection():
    db = _db()
    if db is None:
        return None
    col = db["scam_memory"]
    global _indexes_ok
    if not _indexes_ok:
        try:
            col.create_index([("created_at", -1)])
            col.create_index("fingerprints")
            col.create_index("verdict")
            _indexes_ok = True
        except Exception as e:
            log("scam memory index setup:", e)
    return col


# ---------- normalization ----------

_PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
# Bare hostnames scammers drop in plain text (usps-redeliver.top, pay-now.xyz).
_BARE_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+(?:top|xyz|click|link|info|online|site|club|"
    r"shop|app|live|work|icu|rest|cfd|sbs|zip|mov|country|support|account|secure|login)\b",
    re.I)
_NAME_HINTS = re.compile(
    r"\b(?:grandson|granddaughter|son|daughter|nephew|niece|cousin|"
    r"amazon|apple|microsoft|google|paypal|irs|social security|"
    r"usps|fedex|ups|bank|chase|wells fargo|visa|mastercard|"
    r"tech support|refund|account)\b", re.I)
_PAY_HINTS = re.compile(
    r"\b(?:gift\s*cards?|itunes|steam|google\s*play|wire\s*transfer|"
    r"zelle|venmo|cash\s*app|bitcoin|crypto|western\s*union|"
    r"send\s+(?:me\s+)?\$?\d+|pay\s+\$?\d+)\b", re.I)


def normalize_phone(raw: str) -> Optional[str]:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) >= 8:
        return "+" + digits
    return None


def normalize_email(raw: str) -> Optional[str]:
    m = _EMAIL_RE.search(raw or "")
    return m.group(0).lower() if m else None


def normalize_domain(raw: str) -> Optional[str]:
    s = (raw or "").strip().lower()
    if not s:
        return None
    if "://" not in s and s.startswith("www."):
        s = "http://" + s
    if "://" in s:
        try:
            host = urlparse(s).hostname or ""
        except Exception:
            host = ""
    else:
        # bare host or email domain
        host = s.split("@")[-1].split("/")[0].split("?")[0]
    host = host.lstrip(".").rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    # drop common free-mail noise from fingerprinting "domain of sender" separately
    if not host or "." not in host:
        return None
    return host


def extract_signals(sender: str = "", body: str = "", item: str = "") -> dict:
    """Pull normalized fingerprints from a check for later matching."""
    blob = "%s\n%s" % (sender or "", body or "")
    phones = []
    for m in _PHONE_RE.finditer(blob):
        p = normalize_phone(m.group(0))
        if p and p not in phones:
            phones.append(p)
    emails = []
    for m in _EMAIL_RE.finditer(blob):
        e = m.group(0).lower()
        if e not in emails:
            emails.append(e)
    domains = []
    for m in _URL_RE.finditer(blob):
        d = normalize_domain(m.group(0))
        if d and d not in domains:
            domains.append(d)
    for m in _BARE_HOST_RE.finditer(blob):
        d = normalize_domain(m.group(0))
        if d and d not in domains:
            domains.append(d)
    for e in emails:
        d = normalize_domain(e)
        if d and d not in domains:
            domains.append(d)
    # sender itself may be a phone or email
    sp = normalize_phone(sender)
    if sp and sp not in phones:
        phones.append(sp)
    se = normalize_email(sender)
    if se and se not in emails:
        emails.append(se)
    names = sorted({m.group(0).lower() for m in _NAME_HINTS.finditer(blob)})
    payments = sorted({m.group(0).lower() for m in _PAY_HINTS.finditer(blob)})
    fingerprints = []
    for p in phones:
        fingerprints.append("phone:" + p)
    for e in emails:
        fingerprints.append("email:" + e)
    for d in domains:
        fingerprints.append("domain:" + d)
    for n in names:
        fingerprints.append("name:" + n)
    for p in payments:
        fingerprints.append("pay:" + re.sub(r"\s+", " ", p))
    return {
        "phones": phones,
        "emails": emails,
        "domains": domains,
        "names": names,
        "payments": payments,
        "fingerprints": fingerprints,
        "item": item or "message",
    }


# ---------- store + match ----------

def _ago_label(when: datetime) -> str:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    secs = max(0, (datetime.now(timezone.utc) - when).total_seconds())
    if secs < 3600:
        return "%d minutes ago" % max(1, int(secs // 60))
    if secs < 86400:
        return "%d hours ago" % max(1, int(secs // 3600))
    days = int(secs // 86400)
    if days == 1:
        return "yesterday"
    if days == 2:
        return "two days ago"
    return "%d days ago" % days


def record_incident(check: dict, body: str = "") -> Optional[str]:
    """Save a suspicious/scam check into scam memory. Returns incident id or None."""
    if check.get("error") or check.get("verdict") not in ("SCAM", "SUSPICIOUS"):
        return None
    col = memory_collection()
    if col is None:
        return None
    signals = extract_signals(check.get("sender", ""), body or check.get("text") or check.get("email") or "",
                              check.get("item", ""))
    if not signals["fingerprints"]:
        # still store a soft incident keyed by headline so patterns can soft-match later
        signals["fingerprints"] = ["soft:" + (check.get("headline") or "unknown")[:40].lower()]
    doc = {
        "verdict": check["verdict"],
        "item": check.get("item", "message"),
        "sender": check.get("sender", "unknown"),
        "headline": check.get("headline", ""),
        "reason": check.get("reason", ""),
        "device": check.get("device", ""),
        "question": (check.get("question") or "")[:300],
        "body_preview": (body or check.get("text") or check.get("email") or "")[:500],
        "signals": {k: signals[k] for k in ("phones", "emails", "domains", "names", "payments")},
        "fingerprints": signals["fingerprints"],
        "created_at": check.get("created_at") or datetime.now(timezone.utc),
    }
    try:
        res = col.insert_one(doc)
        log("scam memory: saved incident")
        return str(res.inserted_id)
    except Exception as e:
        log("scam memory save failed:", e)
        return None


def find_related(check: dict, body: str = "", limit: int = 5) -> list:
    """Find prior incidents that share fingerprints with this check (Mongo aggregation)."""
    col = memory_collection()
    if col is None:
        return []
    signals = extract_signals(check.get("sender", ""), body or check.get("text") or check.get("email") or "",
                              check.get("item", ""))
    fps = [f for f in signals["fingerprints"] if not f.startswith("soft:")]
    if not fps:
        return []
    since = datetime.now(timezone.utc) - timedelta(days=config.SCAM_MEMORY_DAYS)
    try:
        pipeline = [
            {"$match": {
                "created_at": {"$gte": since},
                "fingerprints": {"$in": fps},
                "verdict": {"$in": ["SCAM", "SUSPICIOUS"]},
            }},
            {"$addFields": {
                "overlap": {"$size": {"$setIntersection": ["$fingerprints", fps]}},
            }},
            {"$sort": {"overlap": -1, "created_at": -1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "body_preview": 0}},
        ]
        rows = list(col.aggregate(pipeline))
        for r in rows:
            if isinstance(r.get("created_at"), datetime):
                r["when"] = _ago_label(r["created_at"])
                r["created_at"] = r["created_at"].isoformat() + "Z"
        return rows
    except Exception as e:
        log("scam memory match failed:", e)
        return []


def _gemini_relationship(current: dict, related: list, body: str = "") -> Optional[dict]:
    """Ask Gemini whether incidents look coordinated. Soft signal only."""
    if not config.GEMINI_API_KEY or not related:
        return None
    try:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=config.GEMINI_API_KEY,
                             http_options=types.HttpOptions(timeout=8000))
        prior = []
        for r in related[:3]:
            prior.append("- %s (%s): %s from %s. %s"
                         % (r.get("when", "earlier"), r.get("verdict"), r.get("item"),
                            r.get("sender"), r.get("headline")))
        prompt = (
            "You help a family scam guard spot multi-day scam patterns.\n"
            "Current incident: verdict=%s item=%s sender=%s headline=%s\n"
            "Preview: %s\n"
            "Prior incidents:\n%s\n\n"
            "Reply JSON only: {\"linked\": true/false, \"confidence\": \"low|medium|high\", "
            "\"summary\": \"one short plain sentence for the family dashboard\", "
            "\"speech\": \"one short sentence Moly can say out loud to Grandma\"}. "
            "If the link is weak or coincidental, set linked=false. "
            "Never claim a verified connection. Plain words, no jargon."
            % (current.get("verdict"), current.get("item"), current.get("sender"),
               current.get("headline"), (body or "")[:400], "\n".join(prior))
        )
        r = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json", temperature=0.1))
        data = json.loads(r.text)
        if not isinstance(data, dict) or not data.get("linked"):
            return None
        return data
    except Exception as e:
        log("scam memory relationship analysis skipped:", e)
        return None


def analyze_pattern(check: dict, body: str = "") -> Optional[dict]:
    """Compare a new check to memory. Returns a pattern alert dict or None."""
    related = find_related(check, body=body)
    if not related:
        return None
    shared = set()
    for r in related:
        for fp in r.get("fingerprints") or []:
            if fp.startswith(("phone:", "email:", "domain:")):
                shared.add(fp)
    gem = _gemini_relationship(check, related, body=body)
    prev = related[0]
    alert = {
        "kind": "pattern",
        "title": "%s noticed a pattern" % config.APP_NAME,
        "previous_headline": prev.get("headline", "Earlier suspicious message"),
        "previous_when": prev.get("when", "recently"),
        "previous_verdict": prev.get("verdict", "SUSPICIOUS"),
        "current_headline": check.get("headline", ""),
        "shared": sorted(shared)[:6],
        "related_count": len(related),
        "related": related,
        "disclaimer": "Illustrative pattern match, not a verified connection.",
        "confidence": (gem or {}).get("confidence", "medium" if shared else "low"),
        "summary": (gem or {}).get("summary") or (
            "This %s appears connected to a suspicious message received %s."
            % (check.get("item", "message"), prev.get("when", "recently"))),
        "speech": (gem or {}).get("speech") or (
            "This looks connected to a suspicious message from %s. Please be careful."
            % prev.get("when", "recently")),
    }
    return alert


def remember_and_match(check: dict, body: str = "") -> Optional[dict]:
    """Store the incident (if warranted) and return any pattern alert."""
    pattern = None
    try:
        pattern = analyze_pattern(check, body=body)
    except Exception as e:
        log("pattern analysis failed:", e)
    try:
        record_incident(check, body=body)
    except Exception as e:
        log("record incident failed:", e)
    return pattern


def recent_patterns(limit: int = 20) -> list:
    """Recent memory incidents for the family dashboard."""
    col = memory_collection()
    if col is None:
        return []
    since = datetime.now(timezone.utc) - timedelta(days=config.SCAM_MEMORY_DAYS)
    try:
        rows = list(col.find({"created_at": {"$gte": since}}, {"_id": 0, "body_preview": 0})
                    .sort("created_at", -1).limit(min(limit, 100)))
        for r in rows:
            if isinstance(r.get("created_at"), datetime):
                r["when"] = _ago_label(r["created_at"])
                r["created_at"] = r["created_at"].isoformat() + "Z"
        return rows
    except Exception as e:
        log("recent patterns failed:", e)
        return []
