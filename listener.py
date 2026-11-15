"""Background wake-word listener. Records short phrases from the mic, sends them to
Google's free speech recognizer (SpeechRecognition.recognize_google) and starts a
conversational turn when it hears the app's name. After Moly answers, it briefly
keeps listening for a follow-up (yes/no verify, "why?", "call my daughter") without
requiring the wake word again. Uses sounddevice so no Homebrew is needed."""
import difflib
import threading
import time

import numpy as np
import sounddevice as sd
import speech_recognition as sr

import checker
import config
import mac
import voice
from mac import log

RATE = 16000
CHUNK = 1600            # 0.1 s
FOLLOWUP_SECONDS = 18   # listen for a reply after Moly speaks (no wake word)

_busy = threading.Lock()   # one check at a time (mic or button)
_session_id = None         # sticky conversation session across follow-ups


def heard_wake_word(phrase):
    p = phrase.lower()
    for ch in ",.!?":
        p = p.replace(ch, " ")
    words = p.split()
    if any(w in config.WAKE_WORDS for w in words):
        return True
    if any(x in " ".join(words) for x in config.WAKE_PHRASES):
        return True
    # near misses, e.g. "trojans'", "trojann"
    return any(difflib.SequenceMatcher(None, w, config.WAKE_WORDS[0]).ratio() >= 0.8 for w in words)


def _transcripts(rec, audio):
    """Every guess the recognizer made (best first), not just its favourite."""
    res = rec.recognize_google(audio, show_all=True)
    if not isinstance(res, dict):
        return []
    return [a.get("transcript", "") for a in res.get("alternative", []) if a.get("transcript")]


def handle(question, session_id=None):
    """Run one conversational turn. Shared by the wake word and the 'Is this safe?' button."""
    global _session_id
    if not _busy.acquire(blocking=False):
        return None
    try:
        checker.publish("listening")
        # Say "I'm here" right away on a fresh wake; follow-ups stay quiet.
        hello = None
        if not session_id:
            hello = threading.Thread(target=voice.ack, daemon=True)
            hello.start()
        import conversation
        sid = session_id or _session_id
        result = conversation.turn(
            question, session_id=sid, speak=True,
            before_speaking=(hello.join if hello else None))
        if result and result.get("session_id"):
            _session_id = result["session_id"]
        return result
    except Exception as e:
        log("check crashed:", e)
        checker.publish("idle")
        return None
    finally:
        _busy.release()


def _record_phrase(stream, threshold, max_frames=100):
    """Block until someone speaks, return the phrase as int16 bytes (or None)."""
    frames, silent, started = [], 0, False
    while True:
        if _busy.locked():
            return None
        data, _ = stream.read(CHUNK)
        level = float(np.sqrt(np.mean(data.astype(np.float32) ** 2)))
        if level > threshold:
            started, silent = True, 0
        elif started:
            silent += 1
        if started:
            frames.append(data.copy())
            if silent >= 8 or len(frames) >= max_frames:   # 0.8 s quiet, or ~10 s max
                break
    if len(frames) < 5:
        return None
    return np.concatenate(frames).tobytes()


def _listen_followup(stream, threshold, rec):
    """After an answer, listen briefly for a follow-up without the wake word."""
    global _session_id
    if not _session_id:
        return
    deadline = time.time() + FOLLOWUP_SECONDS
    log("listening for a follow-up (%.0fs)…" % FOLLOWUP_SECONDS)
    checker.publish("listening", followup=True, session_id=_session_id)
    while time.time() < deadline:
        if _busy.locked():
            return
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        # Short capture window so we return to wake-word mode promptly.
        raw = _record_phrase(stream, threshold, max_frames=min(100, max(20, int(remaining * 10))))
        if raw is None:
            continue
        try:
            guesses = _transcripts(rec, sr.AudioData(raw, RATE, 2))
        except Exception as e:
            log("speech recognition error:", e)
            continue
        if not guesses:
            continue
        phrase = guesses[0]
        log("follow-up heard:", phrase)
        # Ignore accidental re-wake of the name alone.
        stripped = phrase.lower()
        for w in config.WAKE_WORDS:
            stripped = stripped.replace(w, " ")
        if not stripped.strip() or stripped.strip() in ("hey", "hi", "hello"):
            continue
        result = handle(phrase, session_id=_session_id)
        # If Moly is still awaiting a yes/no (verify), keep the follow-up window open once more.
        if result and result.get("awaiting"):
            _listen_followup(stream, threshold, rec)
        return
    checker.publish("idle")


def _loop():
    rec = sr.Recognizer()
    while True:
        try:
            with sd.InputStream(samplerate=RATE, channels=1, dtype="int16") as stream:
                # measure room noise for one second
                quiet = [stream.read(CHUNK)[0] for _ in range(10)]
                noise = float(np.sqrt(np.mean(np.concatenate(quiet).astype(np.float32) ** 2)))
                threshold = max(300.0, noise * 3)
                log("mic ready, say \"Hey %s\" (noise %.0f, threshold %.0f)" % (config.APP_NAME, noise, threshold))
                while True:
                    raw = _record_phrase(stream, threshold)
                    if raw is None:
                        if _busy.locked():
                            break   # reopen the mic after the app stops talking
                        continue
                    try:
                        guesses = _transcripts(rec, sr.AudioData(raw, RATE, 2))
                    except Exception as e:
                        log("speech recognition error:", e)
                        continue
                    if not guesses:
                        continue
                    log("heard:", guesses[0])
                    if any(heard_wake_word(g) for g in guesses):
                        log("wake word!")
                        result = handle(guesses[0])
                        # Conversational follow-up window (verify yes/no, why, call family).
                        if result is not None:
                            try:
                                _listen_followup(stream, threshold, rec)
                            except Exception as e:
                                log("follow-up listen failed:", e)
                        break       # drop audio captured while speaking
        except Exception as e:
            log("mic unavailable (%s). Use the button instead. Retrying in 10 s." % e)
            time.sleep(10)
        while _busy.locked():
            time.sleep(0.2)
        time.sleep(0.3)


def start():
    # Called from the main thread: load the audio system here first, because
    # loading it for the first time inside the background thread can crash Python.
    try:
        log("microphone:", sd.query_devices(kind="input")["name"])
    except Exception as e:
        log("no microphone found (%s). Use the button instead." % e)
        return
    threading.Thread(target=_loop, daemon=True, name="trojan-listener").start()
