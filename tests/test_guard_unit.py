"""Unit tests for the background guard and the verdict safety net."""
import unittest

from tests import helper
from tests.helper import auth, mac

import checker
import watcher

UNKNOWN, SAVED = "+16825550142", "+12145550199"


class Guard(unittest.TestCase):
    def setUp(self):
        helper.reset()
        self.calls, self.shown, self.read, self.bodies = [], [], [], {}
        self.verdict = "SCAM"
        self.keep = (checker.run_check, checker.show_result, checker.idle_later, checker._save,
                     watcher.voice.speak, watcher.voice.chime, mac.thread_tail, mac.message_body,
                     mac.saved_contacts, watcher.MIN_GAP)

        def run_check(device, question, text=None, silent=False, **k):
            self.calls.append(text)
            if self.verdict == "ERR":
                return {"verdict": "SAFE", "error": "quota", "speech": "x", "headline": "",
                        "reason": "", "action": "", "sender": "", "item": "text"}
            return {"verdict": self.verdict, "speech": "s", "headline": "h", "reason": "r",
                    "action": "a", "sender": UNKNOWN, "item": "text", "scene": "storm", "device": "mac"}
        checker.run_check = run_check
        checker.show_result = lambda r: self.shown.append(r["verdict"])
        checker.idle_later = lambda s=0: None
        checker._save = lambda d: None
        watcher.voice.speak = lambda t: None
        watcher.voice.chime = lambda: None
        mac.thread_tail = lambda s, i, limit=6: []
        mac.message_body = lambda rid: (self.read.append(rid), self.bodies[rid])[1]
        mac.saved_contacts = lambda: {SAVED[-10:]}
        watcher.MIN_GAP = 0
        watcher._alerted.clear()

    def tearDown(self):
        (checker.run_check, checker.show_result, checker.idle_later, checker._save,
         watcher.voice.speak, watcher.voice.chime, mac.thread_tail, mac.message_body,
         mac.saved_contacts, watcher.MIN_GAP) = self.keep

    def arrive(self, sender, body, rid=1):
        self.bodies[rid] = body
        watcher._alerted.clear()
        before = (len(self.calls), len(self.shown), len(self.read))
        watcher.handle_message({"id": rid, "sender": sender})
        return (len(self.calls) - before[0], len(self.shown) - before[1], len(self.read) - before[2])

    def test_message_from_a_saved_contact_is_never_read(self):
        self.assertEqual(self.arrive(SAVED, "You won the lottery! Send your bank account number"), (0, 0, 0))

    def test_ordinary_messages_from_unknown_numbers_stay_silent(self):
        for body in ("Hi, how are you?", "Are we still on for lunch tomorrow?",
                     "look at this https://youtube.com/shorts/abc", "Happy birthday!"):
            self.assertEqual(self.arrive(UNKNOWN, body), (0, 0, 1), body)

    def test_risky_messages_from_unknown_numbers_alert(self):
        for body in ("Congratulations! You won the $1,000,000 Mega Lottery. Pay the $50 fee",
                     "Please send your SSN to verify your identity",
                     "Your bank account is locked. Send card number and CVV",
                     "You won a free iPhone! claim at http://apple-gift.top/win",
                     "Track your parcel: http://usps-redeliver.top/x",
                     "Grandma I'm in jail, I need bail money, don't tell mom"):
            self.assertEqual(self.arrive(UNKNOWN, body), (1, 1, 1), body)

    def test_model_saying_safe_means_no_alert(self):
        self.verdict = "SAFE"
        self.assertEqual(self.arrive(UNKNOWN, "what is your new number?")[1], 0)

    def test_model_down_still_warns_on_clear_scams_only(self):
        self.verdict = "ERR"
        self.assertEqual(self.arrive(UNKNOWN, "You won the lottery, pay $20 release fee")[1], 1)
        self.assertEqual(self.arrive(UNKNOWN, "urgent, call me")[1], 0)

    def test_guard_pauses_when_contacts_cannot_be_read(self):
        mac.saved_contacts = lambda: None
        self.assertEqual(self.arrive(UNKNOWN, "you won the lottery"), (0, 0, 0))

    def test_second_alert_about_the_same_sender_waits(self):
        self.arrive(UNKNOWN, "you won the lottery")
        n = len(self.calls)
        self.bodies[2] = "you won the jackpot"
        watcher.handle_message({"id": 2, "sender": UNKNOWN})
        self.assertEqual(len(self.calls), n)

    def test_number_stops_being_watched_once_saved(self):
        mac.saved_contacts = lambda: {UNKNOWN[-10:], SAVED[-10:]}
        self.assertEqual(self.arrive(UNKNOWN, "you won the lottery"), (0, 0, 0))


class VerdictSafetyNet(unittest.TestCase):
    """The rule layer may calm a false alarm about a greeting, never a real scam."""

    def run_case(self, body, model_says, sender_known=False):
        status = "KNOWN. She has written to this sender before." if sender_known \
            else "UNKNOWN. She has never written to this sender."
        text = "From: +16825550142\nSender status: %s\nReceived: 1 minutes ago\n\n%s" % (status, body)
        r = {"verdict": model_says, "item": "text", "sender": "+16825550142", "headline": "h",
             "reason": "r", "action": "a", "speech": "s", "scene": "harbor"}
        return checker.calibrate_verdict(r, text=text)["verdict"]

    def test_scams_are_never_softened_to_safe(self):
        for body in ("Congratulations! You won the $1,000,000 Mega Lottery. Pay the $50 fee",
                     "Send your SSN to verify your identity",
                     "Your bank account is locked. Send card number and CVV",
                     "You won a free iPhone! claim at http://apple-gift.top/win",
                     "Grandma I'm in jail, I need bail money, don't tell mom"):
            for model in ("SCAM", "SUSPICIOUS"):
                self.assertNotEqual(self.run_case(body, model), "SAFE", body)

    def test_greetings_and_known_links_are_not_alarms(self):
        for body in ("Hi, how are you?", "look at this https://youtube.com/shorts/abc"):
            self.assertEqual(self.run_case(body, "SAFE"), "SAFE", body)

    def test_lookalike_links_are_not_trusted(self):
        for url in ("http://youtube.com.claim-prize.top/x", "https://bit.ly/abc", "http://chase-verify.co"):
            self.assertFalse(checker._is_trusted_link(url), url)
        for url in ("https://youtube.com/watch?v=1", "https://www.amazon.com/dp/1", "https://m.youtube.com/x"):
            self.assertTrue(checker._is_trusted_link(url), url)


if __name__ == "__main__":
    unittest.main()
