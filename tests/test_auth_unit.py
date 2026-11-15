"""Unit tests for accounts: validation rules, sign-up, sign-in, password reset."""
import json
import time
import unittest

from tests import helper
from tests.helper import auth, config, make_account, person, born


def error_of(fn, *a, **k):
    """Call fn expecting an AuthError; return it."""
    try:
        fn(*a, **k)
    except auth.AuthError as e:
        return e
    raise AssertionError("expected an AuthError from %s" % fn.__name__)


class Base(unittest.TestCase):
    def setUp(self):
        helper.reset()


class Rules(Base):
    def test_phone_is_normalised(self):
        for raw in ("2145550100", "(214) 555-0100", "214-555-0100", "1 214 555 0100", "+12145550100"):
            self.assertEqual(auth.normalize_phone(raw), "+12145550100", raw)

    def test_bad_phones_are_rejected(self):
        for raw in ("", "123", "21455501", "abcdefghij", "214555010012345678", None):
            self.assertEqual(error_of(auth.normalize_phone, raw).field, "phone", raw)

    def test_age_is_counted_in_whole_years(self):
        from datetime import date
        today = date(2026, 11, 15)
        self.assertEqual(auth.age_on("1976-11-15", today), 50)
        self.assertEqual(auth.age_on("1976-11-16", today), 49)
        self.assertEqual(auth.age_on("2008-11-16", today), 17)

    def test_bad_dates_are_rejected(self):
        for raw in ("", "nope", "2999-01-01", "1800-01-01", "03/02/1950", None):
            self.assertEqual(error_of(auth.age_on, raw).field, "dob", raw)

    def test_emergency_contact_is_required_at_18_or_younger_and_50_or_older(self):
        expect = {5: True, 17: True, 18: True, 19: False, 35: False, 49: False, 50: True, 51: True, 90: True}
        for years, need in expect.items():
            self.assertEqual(auth.needs_contact(born(years)), need, years)

    def test_password_rule(self):
        good = ["Passw0rd", "Aa1aaaaa", "Passw0rd" + "x" * 10, "Zz9 zzzz!"]
        bad = ["", None, "Passw0r", "Aa1", "Passw0rd" + "x" * 11, "passw0rdd", "PASSW0RDD",
               "Passwordd", "12345678", "        "]
        for pw in good:
            auth.check_password(pw)          # must not raise
        for pw in bad:
            self.assertEqual(error_of(auth.check_password, pw).field, "password", repr(pw))

    def test_passwords_of_7_and_19_characters_are_rejected_and_8_and_18_accepted(self):
        self.assertTrue(error_of(auth.check_password, "Abcde1x"))            # 7
        auth.check_password("Abcde1xy")                                        # 8
        auth.check_password("Abcde1" + "y" * 12)                               # 18
        self.assertTrue(error_of(auth.check_password, "Abcde1" + "y" * 13))  # 19


class SignUp(Base):
    def test_every_missing_or_bad_field_is_named(self):
        cases = [("first_name", ""), ("last_name", "  "), ("phone", "12"),
                 ("dob", ""), ("password", "short1A"), ("password", "alllowercase1"),
                 ("contact_phone", ""), ("contact_name", ""), ("contact_phone", "2145550100"),
                 ("contact_phone", "55")]
        for field, value in cases:
            helper.reset()
            e = error_of(auth.start_signup, **person(**{field: value}))
            self.assertEqual(e.field, field, "%s=%r -> %s" % (field, value, e))
            self.assertIsNone(auth._get_user("+12145550100"), "no account for an invalid sign-up")
            self.assertIsNone(auth.current())

    def test_short_password_never_creates_an_account(self):
        for pw in ("Ab1", "Abcde1x", "", "abcdefgh", "Abcde1" + "y" * 13):
            e = error_of(auth.start_signup, **person(password=pw))
            self.assertEqual(e.field, "password", repr(pw))
            self.assertIsNone(auth._get_user("+12145550100"))

    def test_both_consents_are_required(self):
        for change in ({"risk_consent": False}, {"privacy_consent": False}):
            helper.reset()
            self.assertEqual(error_of(auth.start_signup, **person(**change)).field, "consent")
            self.assertIsNone(auth._get_user("+12145550100"))

    def test_contact_is_optional_between_19_and_49(self):
        auth.start_signup(**person(dob=born(30), contact_name="", contact_phone=""))
        self.assertEqual(auth.current()["contact_phone"], "")

    def test_valid_sign_up_creates_the_account_and_signs_in(self):
        out = auth.start_signup(**person())
        self.assertEqual(out["name"], "Ana Diaz")
        user = auth._get_user("+12145550100")
        self.assertEqual((user["first_name"], user["last_name"], user["name"]), ("Ana", "Diaz", "Ana Diaz"))
        self.assertTrue(user["consent"]["risk_version"])
        self.assertEqual(user["contact_phone"], "+12145550199")
        self.assertEqual(auth.current()["phone"], "+12145550100")
        self.assertEqual(config.FAMILY_PHONE, "+12145550199")
        self.assertEqual(config.USER_PHONE, "+12145550100")

    def test_password_is_never_stored_or_kept_in_the_session(self):
        make_account()
        stored = auth.FILE.read_text() + auth.SESSION.read_text()
        self.assertNotIn("Passw0rdd", stored)
        session = json.loads(auth.SESSION.read_text())
        self.assertNotIn("password", session["user"])
        self.assertNotIn("salt", session["user"])

    def test_same_number_cannot_sign_up_twice(self):
        make_account()
        auth.logout()
        self.assertEqual(error_of(auth.start_signup, **person(first_name="Other")).field, "phone")
        self.assertEqual(auth._get_user("+12145550100")["first_name"], "Ana")
        self.assertIsNone(auth.current())


class SignIn(Base):
    def setUp(self):
        super().setUp()
        make_account()
        auth.logout()

    def test_right_password_signs_in(self):
        auth.login("(214) 555-0100", "Passw0rdd")
        self.assertEqual(auth.current()["name"], "Ana Diaz")

    def test_wrong_password_and_unknown_number_look_the_same(self):
        a = str(error_of(auth.login, "2145550100", "Wrongpass1"))
        b = str(error_of(auth.login, "2145550111", "Passw0rdd"))
        self.assertEqual(a, b)
        self.assertIsNone(auth.current())

    def test_empty_short_and_near_miss_passwords_never_sign_in(self):
        for pw in ("", None, "P", "Passw0rd", "passw0rdd", "Passw0rdd ", "Passw0rddd"):
            error_of(auth.login, "2145550100", pw)
            self.assertIsNone(auth.current(), repr(pw))
            auth._fails.clear()

    def test_five_wrong_passwords_pause_sign_in_even_for_the_right_one(self):
        for _ in range(auth.LOGIN_TRIES):
            error_of(auth.login, "2145550100", "Wrongpass1")
        self.assertIn("many", str(error_of(auth.login, "2145550100", "Passw0rdd")).lower())
        self.assertIsNone(auth.current())

    def test_pause_ends_after_a_minute(self):
        for _ in range(auth.LOGIN_TRIES):
            error_of(auth.login, "2145550100", "Wrongpass1")
        count, when = auth._fails["+12145550100"]
        auth._fails["+12145550100"] = (count, when - auth.LOGIN_PAUSE - 1)
        auth.login("2145550100", "Passw0rdd")

    def test_sign_out(self):
        auth.login("2145550100", "Passw0rdd")
        auth.logout()
        self.assertIsNone(auth.current())
        self.assertEqual(config.FAMILY_PHONE, "")


class ForgotPassword(Base):
    """Reset is proved with the phone number and the date of birth on the account."""
    DOB = "1950-03-02"

    def setUp(self):
        super().setUp()
        make_account()
        auth.logout()

    def test_wrong_date_and_unknown_number_look_the_same_and_give_no_ticket(self):
        a = str(error_of(auth.start_reset, "2145550100", "1951-01-01"))
        b = str(error_of(auth.start_reset, "2145550111", self.DOB))
        self.assertEqual(a, b)
        self.assertEqual(auth._pending, {})

    def test_nobody_is_signed_in_at_any_step_of_forgot_password(self):
        ticket = auth.start_reset("2145550100", self.DOB)["ticket"]
        self.assertIsNone(auth.current())
        auth.reset_password("2145550100", ticket, "Newpass123")
        self.assertIsNone(auth.current(), "changing the password must not sign anyone in")
        self.assertFalse(auth.status()["signed_in"])

    def test_password_cannot_be_changed_without_proving_who_it_is(self):
        for ticket in ("", "guess", None):
            self.assertTrue(error_of(auth.reset_password, "2145550100", ticket, "Newpass123"))
        error_of(auth.start_reset, "2145550100", "1951-01-01")
        self.assertTrue(error_of(auth.reset_password, "2145550100", "", "Newpass123"))
        auth.login("2145550100", "Passw0rdd")          # old password still the only one

    def test_new_password_must_follow_the_rule(self):
        ticket = auth.start_reset("2145550100", self.DOB)["ticket"]
        for pw in ("Ab1", "Abcde1x", "alllowercase1", "Passw0rd" + "x" * 11, ""):
            self.assertEqual(error_of(auth.reset_password, "2145550100", ticket, pw).field, "password", pw)
        auth.reset_password("2145550100", ticket, "Newpass123")

    def test_after_reset_only_the_new_password_works_and_ticket_is_spent(self):
        ticket = auth.start_reset("2145550100", self.DOB)["ticket"]
        auth.reset_password("2145550100", ticket, "Newpass123")
        self.assertTrue(error_of(auth.reset_password, "2145550100", ticket, "Another123"))
        self.assertTrue(error_of(auth.login, "2145550100", "Passw0rdd"))
        auth._fails.clear()
        auth.login("2145550100", "Newpass123")

    def test_ticket_for_one_number_does_not_work_for_another(self):
        auth.logout()
        auth.start_signup(**person(phone="2145550155", first_name="Bo"))
        auth.logout()
        ticket = auth.start_reset("2145550155", self.DOB)["ticket"]
        self.assertTrue(error_of(auth.reset_password, "2145550100", ticket, "Newpass123"))

    def test_ticket_expires(self):
        ticket = auth.start_reset("2145550100", self.DOB)["ticket"]
        auth._pending["+12145550100"]["ticket_until"] = time.time() - 1
        self.assertTrue(error_of(auth.reset_password, "2145550100", ticket, "Newpass123"))

    def test_five_wrong_dates_pause_reset_even_for_the_right_one(self):
        for _ in range(auth.LOGIN_TRIES):
            error_of(auth.start_reset, "2145550100", "1951-01-01")
        self.assertIn("many", str(error_of(auth.start_reset, "2145550100", self.DOB)).lower())

    def test_reset_clears_the_sign_in_pause(self):
        for _ in range(auth.LOGIN_TRIES):
            error_of(auth.login, "2145550100", "Wrongpass1")
        ticket = auth.start_reset("2145550100", self.DOB)["ticket"]
        auth.reset_password("2145550100", ticket, "Newpass123")
        auth.login("2145550100", "Newpass123")


class ConsentContactAndSessions(Base):
    def test_new_consent_version_must_be_accepted_again(self):
        make_account()
        old = auth.RISK_CONSENT_VERSION
        auth.RISK_CONSENT_VERSION = "next-version"
        try:
            self.assertIsNone(auth.current())
            self.assertTrue(auth.status()["consent_required"])
            self.assertTrue(error_of(auth.accept_consent, True, False))
            auth.accept_consent(True, True)
            self.assertIsNotNone(auth.current())
        finally:
            auth.RISK_CONSENT_VERSION = old

    def test_emergency_contact_can_be_changed_but_not_removed_when_required(self):
        make_account()
        auth.set_contact("Sam", "214 555 0188")
        self.assertEqual(config.FAMILY_PHONE, "+12145550188")
        self.assertEqual(error_of(auth.set_contact, "", "").field, "contact_phone")
        self.assertEqual(error_of(auth.set_contact, "Me", "2145550100").field, "contact_phone")

    def test_two_browsers_on_the_hosted_server_do_not_share_a_sign_in(self):
        make_account()
        auth.logout()
        a, b = {"user": None, "changed": False}, {"user": None, "changed": False}
        token = auth._web.set(a)
        try:
            auth.login("2145550100", "Passw0rdd")
            self.assertEqual(auth.current()["phone"], "+12145550100")
        finally:
            auth._web.reset(token)
        token = auth._web.set(b)
        try:
            self.assertIsNone(auth.current())
        finally:
            auth._web.reset(token)
        self.assertTrue(a["changed"] and a["user"])
        self.assertIsNone(auth.current(), "the Mac's own sign-in must not change")


if __name__ == "__main__":
    unittest.main()
