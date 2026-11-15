"""The voice. Clear, calm, never silent.

Order of preference (Cal Hacks FaceTimeOS-style clarity first):
  1. Fish Audio (if FISH_API_KEY is set)  <- same TTS stack as Cal Hacks 12.0 winners
  2. ElevenLabs (if ELEVENLABS_API_KEY is set)
  3. Gemini's natural voice (free, same GEMINI_API_KEY)   <- the default
  4. macOS `say` with the best installed voice  <- always works, used on any failure
The wake-up line and the chime are rendered once and cached, so they play instantly."""
import hashlib
import math
import struct
import subprocess
import threading
import wave

import requests

import config
import mac
from mac import log

ACK = "Mm-hmm?"      # the soft "go on" sound, like Siri
CACHE = config.ROOT / ".cache"
CHIME = CACHE / "chime.wav"

_lock = threading.Lock()        # one voice at a time
_cloud_ok = True                # flips to False after a cloud failure, so we stop waiting on it


def _key(text, tag):
    return hashlib.md5(("%s|%s" % (tag, text)).encode()).hexdigest()[:16]


def _play(path):
    subprocess.run(["afplay", str(path)], timeout=60, check=True)


# ---------- cloud voices (optional) ----------

def _elevenlabs(text):
    r = requests.post(
        "https://api.elevenlabs.io/v1/text-to-speech/%s" % config.ELEVENLABS_VOICE_ID,
        params={"output_format": "mp3_44100_128"},
        headers={"xi-api-key": config.ELEVENLABS_API_KEY},
        json={"text": text, "model_id": "eleven_flash_v2_5",
              "voice_settings": {"stability": 0.6, "similarity_boost": 0.8, "speed": 0.95}},
        timeout=8)
    r.raise_for_status()
    return r.content


def _fish(text):
    """Fish Audio TTS — clear neural voice (same provider as Cal Hacks FaceTimeOS)."""
    body = {
        "text": text,
        "format": "mp3",
        "mp3_bitrate": 192,
        "normalize": True,
        "latency": "normal",
        "language": "en",
        "prosody": {"speed": 0.95, "volume": 0},
    }
    if config.FISH_VOICE_ID:
        body["reference_id"] = config.FISH_VOICE_ID
    r = requests.post(
        "https://api.fish.audio/v1/tts",
        headers={
            "Authorization": "Bearer " + config.FISH_API_KEY,
            "model": "s1",
        },
        json=body,
        timeout=12,
    )
    r.raise_for_status()
    return r.content


def _gemini(text):
    """Gemini's natural voice. Returns WAV bytes."""
    import io
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=config.GEMINI_API_KEY,
                          http_options=types.HttpOptions(timeout=12000))
    cfg = types.GenerateContentConfig(
        response_modalities=["AUDIO"],
        speech_config=types.SpeechConfig(voice_config=types.VoiceConfig(
            prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name=config.GEMINI_VOICE))))
    prompt = text    # only the words to speak: this model reads any instructions aloud
    last = None
    for model in dict.fromkeys([config.GEMINI_TTS_MODEL, "gemini-3.8-flash-tts"]):
        try:
            r = client.models.generate_content(model=model, contents=prompt, config=cfg)
            part = r.candidates[0].content.parts[0].inline_data
            if "wav" in (part.mime_type or "").lower():
                return part.data
            rate = 24000                      # raw PCM: wrap it in a WAV header
            for bit in (part.mime_type or "").split(";"):
                if bit.strip().startswith("rate="):
                    rate = int(bit.split("=")[1])
            buf = io.BytesIO()
            with wave.open(buf, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(rate)
                w.writeframes(part.data)
            return buf.getvalue()
        except Exception as e:
            last = e
    raise last


def _cloud_file(text):
    """Path to an audio file of `text` from a cloud voice, or None (no key / failed)."""
    global _cloud_ok
    # Prefer Fish Audio when configured (Cal Hacks clarity), then ElevenLabs, then Gemini.
    if config.FISH_API_KEY:
        name, fn, ext = "fish", _fish, "mp3"
    elif config.ELEVENLABS_API_KEY:
        name, fn, ext = "elevenlabs", _elevenlabs, "mp3"
    elif config.GEMINI_API_KEY and config.GEMINI_VOICE.lower() != "off":
        name, fn, ext = "gemini-" + config.GEMINI_VOICE, _gemini, "wav"
    else:
        return None
    path = CACHE / ("%s.%s" % (_key(text, name), ext))
    if path.exists():
        return path
    if not _cloud_ok:
        return None
    try:
        audio = fn(text)
        if len(audio) < 500:
            raise RuntimeError("empty audio")
        path.write_bytes(audio)
        return path
    except Exception as e:
        _cloud_ok = False
        log("%s voice failed (%s). Using the Mac voice from now on." % (name, str(e)[:120]))
        return None


# ---------- speaking ----------

def speak(text):
    """Say `text` out loud and wait until it is finished. Never raises, never silent."""
    if not text:
        return
    with _lock:
        path = _cloud_file(text)
        if path:
            try:
                _play(path)
                return
            except Exception as e:
                log("could not play cloud audio:", e)
        mac.say(text)


def _ack_file():
    """The wake-up line, pre-rendered so it starts in well under a second."""
    path = _cloud_file(ACK)
    if path:
        return path
    path = CACHE / ("%s.aiff" % _key(ACK, "say|%s|%s" % (mac.best_voice(), config.TROJAN_RATE)))
    if not path.exists():
        cmd = ["say", "-r", str(config.TROJAN_RATE), "-o", str(path)]
        if mac.best_voice():
            cmd += ["-v", mac.best_voice()]
        subprocess.run(cmd + [ACK], timeout=20, check=True)
    return path


def ack():
    """Instant acknowledgment when woken."""
    with _lock:
        try:
            _play(_ack_file())
            return
        except Exception as e:
            log("cached acknowledgment failed:", e)
        mac.say(ACK)


# ---------- the gentle chime before a scam warning ----------

def _make_chime():
    """Two soft, warm bell notes that fade out. Deliberately not an alarm."""
    rate, notes = 44100, [(659.25, 0.0), (880.0, 0.22)]     # E5 then A5
    total = int(rate * 1.5)
    samples = [0.0] * total
    for freq, start in notes:
        for i in range(int(start * rate), total):
            t = (i - start * rate) / rate
            env = min(1.0, t / 0.012) * math.exp(-3.4 * t)      # soft attack, slow fade
            samples[i] += env * (math.sin(2 * math.pi * freq * t)
                                 + 0.22 * math.sin(2 * math.pi * 2 * freq * t))
    with wave.open(str(CHIME), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", int(max(-1, min(1, s * 0.2)) * 32767))
                               for s in samples))


def chime():
    with _lock:
        try:
            if not CHIME.exists():
                _make_chime()
            _play(CHIME)
        except Exception as e:
            log("chime failed:", e)


def prepare():
    """Run once at startup (in the background): render the chime and the wake-up line."""
    def _go():
        try:
            CACHE.mkdir(exist_ok=True)
            if not CHIME.exists():
                _make_chime()
            _ack_file()
            who = ("ElevenLabs" if config.ELEVENLABS_API_KEY else
                   "Fish Audio" if config.FISH_API_KEY else
                   "Gemini voice \"%s\"" % config.GEMINI_VOICE
                   if _cloud_ok and config.GEMINI_API_KEY and config.GEMINI_VOICE.lower() != "off"
                   else "Mac voice \"%s\"" % (mac.best_voice() or "system default"))
            log("voice ready:", who)
        except Exception as e:
            log("voice warm-up failed (will still speak):", e)
    threading.Thread(target=_go, daemon=True).start()
