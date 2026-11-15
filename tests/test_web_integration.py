"""Integration tests for the hosted site (server.py): real HTTP requests through the
whole stack, with only the outside world faked (Gemini, database)."""
import unittest

from fastapi.testclient import TestClient

from tests import helper
from tests.helper import person

import checker
import server

VERDICT = {"verdict": "SCAM", "item": "text", "sender": "unknown", "headline": "This is a scam.",
           "reason": "It asks for a fee to claim a prize.", "action": "Do not pay anything.",
           "speech": "This is a scam. Do not pay anything.", "scene": "siren"}
asked = []


def fake_gemini(question, text, email, image_bytes, device):
    asked.append({"text": text, "image": bool(image_bytes)})
    if fake_gemini.fail:
        raise RuntimeError("quota")
    return dict(VERDICT, verdict=fake_gemini.verdict)


fake_gemini.verdict, fake_gemini.fail = "SCAM", False
checker._ask_gemini = fake_gemini
checker.calibrate_verdict = lambda r, text=None, email=None: r     # tested on its own


def step(client, name, **body):
    r = client.post("/api/auth/" + name, json=body)
    assert r.status_code == 200, (name, r.status_code, r.text)
    return r.json()


def sign_up(client, **changes):
    p = person(**changes)
    out = step(client, "signup", **p)
    assert out["ok"], out
    return p


class Web(unittest.TestCase):
    def setUp(self):
        helper.reset()
        server._memory_sessions.clear()
        server._recent.clear()
        del asked[:]
        fake_gemini.verdict, fake_gemini.fail = "SCAM", False
        self.c = TestClient(server.app)

    def state(self, client=None):
        return (client or self.c).get("/api/auth/state").json()

    # ----- pages -----
    def test_home_page_is_served_in_web_mode(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn('const WEB = "web" === "web"', r.text)
        self.assertNotIn("{{", r.text)
        self.assertEqual(self.c.get("/healthz").json(), {"ok": True})

    def test_unknown_step_is_404(self):
        self.assertEqual(self.c.post("/api/auth/nope", json={}).status_code, 404)

    # ----- sign-up -----
    def test_sign_up_then_stays_signed_in(self):
        out = step(self.c, "signup", **person())
        self.assertTrue(out["ok"] and out["state"]["signed_in"])
        self.assertEqual(out["state"]["user"]["name"], "Ana Diaz")
        self.assertTrue(self.state()["signed_in"])

    def test_seven_character_password_is_refused_by_the_server(self):
        out = step(self.c, "signup", **person(password="Abcde1x"))
        self.assertEqual((out["ok"], out["field"]), (False, "password"))
        self.assertFalse(self.state()["signed_in"])
        self.assertFalse(step(self.c, "login", phone="2145550100", password="Abcde1x")["ok"])

    def test_bad_fields_come_back_with_the_field_name(self):
        for field, value in (("phone", "12"), ("last_name", ""), ("contact_phone", ""), ("dob", "")):
            out = step(self.c, "signup", **person(**{field: value}))
            self.assertEqual((out["ok"], out["field"]), (False, field), out)
            self.assertFalse(self.state()["signed_in"])

    def test_removed_code_steps_do_not_exist(self):
        for name in ("verify", "resend", "forgot_verify", "email", "email_verify", "finish"):
            self.assertEqual(self.c.post("/api/auth/" + name, json={}).status_code, 404, name)

    # ----- sessions -----
    def test_cookie_is_http_only_and_secure_behind_https(self):
        r = self.c.post("/api/auth/signup", json=person(), headers={"x-forwarded-proto": "https"})
        cookie = r.headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("secure", cookie)
        self.assertIn("samesite=lax", cookie)

    def test_another_browser_is_not_signed_in(self):
        sign_up(self.c)
        other = TestClient(server.app)
        self.assertFalse(self.state(other)["signed_in"])
        self.assertEqual(other.post("/api/check", json={"text": "hi"}).status_code, 401)

    def test_sign_out_ends_the_session_for_good(self):
        sign_up(self.c)
        old = self.c.cookies.get(server.COOKIE)
        step(self.c, "logout")
        self.assertFalse(self.state()["signed_in"])
        thief = TestClient(server.app)
        thief.cookies.set(server.COOKIE, old)
        self.assertFalse(self.state(thief)["signed_in"], "an old cookie must not work after sign-out")

    def test_made_up_cookie_is_ignored(self):
        self.c.cookies.set(server.COOKIE, "not-a-real-session")
        self.assertFalse(self.state()["signed_in"])

    # ----- sign-in -----
    def test_sign_in_and_lockout(self):
        sign_up(self.c)
        step(self.c, "logout")
        self.assertFalse(step(self.c, "login", phone="2145550100", password="Wrongpass1")["ok"])
        self.assertFalse(self.state()["signed_in"])
        self.assertTrue(step(self.c, "login", phone="2145550100", password="Passw0rdd")["ok"])
        step(self.c, "logout")
        for _ in range(5):
            step(self.c, "login", phone="2145550100", password="Wrongpass1")
        out = step(self.c, "login", phone="2145550100", password="Passw0rdd")
        self.assertFalse(out["ok"])
        self.assertIn("many", out["error"].lower())

    # ----- forgot password -----
    def test_forgot_password_needs_the_right_details_and_never_signs_in(self):
        sign_up(self.c)
        step(self.c, "logout")
        # nothing proved, wrong date, made-up ticket: nothing changes
        self.assertFalse(step(self.c, "reset", phone="2145550100", ticket="", password="Newpass123")["ok"])
        self.assertFalse(step(self.c, "forgot", phone="2145550100", dob="1951-01-01")["ok"])
        self.assertFalse(step(self.c, "reset", phone="2145550100", ticket="guess", password="Newpass123")["ok"])
        out = step(self.c, "forgot", phone="2145550100", dob="1950-03-02")
        self.assertTrue(out["ok"])
        self.assertFalse(out["state"]["signed_in"])
        self.assertFalse(self.state()["signed_in"])
        short = step(self.c, "reset", phone="2145550100", ticket=out["ticket"], password="Abcde1x")
        self.assertEqual((short["ok"], short["field"]), (False, "password"))
        done = step(self.c, "reset", phone="2145550100", ticket=out["ticket"], password="Newpass123")
        self.assertTrue(done["ok"])
        self.assertFalse(done["state"]["signed_in"], "resetting the password must not sign in")
        self.assertFalse(self.state()["signed_in"])
        self.assertEqual(self.c.post("/api/check", json={"text": "hi"}).status_code, 401)
        self.assertFalse(step(self.c, "login", phone="2145550100", password="Passw0rdd")["ok"])
        self.assertTrue(step(self.c, "login", phone="2145550100", password="Newpass123")["ok"])

    def test_forgot_password_for_unknown_number_looks_like_a_wrong_date(self):
        sign_up(self.c)
        step(self.c, "logout")
        a = step(self.c, "forgot", phone="2145550100", dob="1951-01-01")
        b = step(self.c, "forgot", phone="2145550111", dob="1950-03-02")
        self.assertEqual((a["ok"], a["error"]), (b["ok"], b["error"]))

    # ----- the check -----
    def test_check_needs_sign_in(self):
        self.assertEqual(self.c.post("/api/check", json={"text": "hi"}).status_code, 401)
        self.assertEqual(asked, [])

    def test_failed_sign_up_cannot_check(self):
        step(self.c, "signup", **person(password="Abcde1x"))
        self.assertEqual(self.c.post("/api/check", json={"text": "hi"}).status_code, 401)

    def test_scam_text_returns_verdict_and_a_message_for_the_contact(self):
        sign_up(self.c)
        r = self.c.post("/api/check", json={"text": "You won the lottery, pay $50"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual((body["verdict"], body["failed"]), ("SCAM", False))
        self.assertTrue(body["speech"])
        self.assertEqual(body["contact"]["phone"], "+12145550199")
        self.assertIn("Maya", body["contact"]["message"])
        self.assertEqual(asked[0]["text"], "You won the lottery, pay $50")
        self.assertEqual(helper.imessages, [], "the hosted server never sends messages itself")

    def test_safe_verdict_has_no_contact_message(self):
        sign_up(self.c)
        fake_gemini.verdict = "SAFE"
        self.assertNotIn("contact", self.c.post("/api/check", json={"text": "Hi, how are you?"}).json())

    def test_no_contact_on_the_account_means_no_contact_message(self):
        sign_up(self.c, dob=helper.born(30), contact_name="", contact_phone="")
        self.assertNotIn("contact", self.c.post("/api/check", json={"text": "You won"}).json())

    def test_screenshot_is_passed_to_the_model(self):
        sign_up(self.c)
        r = self.c.post("/api/check", json={"image_b64": "data:image/jpeg;base64,/9j/4AAQSkZJRg=="})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(asked[0]["image"])

    def test_empty_and_oversized_checks_are_refused(self):
        sign_up(self.c)
        self.assertEqual(self.c.post("/api/check", json={}).status_code, 400)
        self.assertEqual(self.c.post("/api/check", json={"text": "   "}).status_code, 400)
        big = "x" * (server.MAX_IMAGE_CHARS + 1)
        self.assertEqual(self.c.post("/api/check", json={"image_b64": big}).status_code, 413)
        self.assertEqual(asked, [])

    def test_model_failure_is_reported_as_failed_not_as_safe(self):
        sign_up(self.c)
        fake_gemini.fail = True
        body = self.c.post("/api/check", json={"text": "You won"}).json()
        self.assertTrue(body["failed"])
        self.assertNotIn("contact", body)

    def test_too_many_checks_in_a_minute_are_slowed_down(self):
        sign_up(self.c)
        codes = [self.c.post("/api/check", json={"text": "hi"}).status_code
                 for _ in range(server.CHECKS_PER_MINUTE + 1)]
        self.assertEqual(codes, [200] * server.CHECKS_PER_MINUTE + [429])

    def test_history_is_private(self):
        self.assertEqual(self.c.get("/api/checks").status_code, 401)


if __name__ == "__main__":
    unittest.main()
