"""Integration tests for the Mac app's own routes (app.py), without the window, the
microphone or the background guard."""
import unittest

from fastapi.testclient import TestClient

from tests import helper
from tests.helper import auth, person

import app as mac_app


def step(client, name, **body):
    r = client.post("/api/auth/" + name, json=body)
    assert r.status_code == 200, (name, r.status_code, r.text)
    return r.json()


class MacApp(unittest.TestCase):
    def setUp(self):
        helper.reset()
        self.c = TestClient(mac_app.app, client=("127.0.0.1", 50000))

    def test_page_is_served_in_mac_mode(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn('const WEB = "mac" === "web"', r.text)

    def test_accounts_cannot_be_reached_from_another_computer(self):
        outside = TestClient(mac_app.app, client=("192.168.1.50", 50000))
        self.assertEqual(outside.get("/api/auth/state").status_code, 403)
        self.assertEqual(outside.post("/api/auth/login", json={}).status_code, 403)
        self.assertEqual(outside.post("/ask").status_code, 403)

    def test_swipe_needs_sign_in(self):
        self.assertEqual(self.c.post("/ask").status_code, 401)

    def test_sign_up_then_alerts_go_to_the_contact(self):
        out = step(self.c, "signup", **person())
        self.assertTrue(out["ok"] and out["state"]["signed_in"])
        self.assertEqual(helper.config.FAMILY_PHONE, "+12145550199")
        self.assertEqual(auth.current()["name"], "Ana Diaz")

    def test_short_password_is_refused(self):
        out = step(self.c, "signup", **person(password="Abcde1x"))
        self.assertEqual((out["ok"], out["field"]), (False, "password"))

    def test_forgot_password_does_not_sign_in_on_the_mac(self):
        helper.make_account()
        auth.logout()
        self.assertFalse(step(self.c, "forgot", phone="2145550100", dob="1951-01-01")["ok"])
        t = step(self.c, "forgot", phone="2145550100", dob="1950-03-02")["ticket"]
        done = step(self.c, "reset", phone="2145550100", ticket=t, password="Newpass123")
        self.assertTrue(done["ok"])
        self.assertFalse(done["state"]["signed_in"])
        self.assertIsNone(auth.current())
        self.assertEqual(self.c.post("/ask").status_code, 401)

    def test_unknown_step_is_404(self):
        self.assertEqual(self.c.post("/api/auth/nope", json={}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
