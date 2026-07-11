# test_billing_enforcement.py
"""Tests for subscription/plan enforcement:

  * Per-plan scan quota (free = 1 lifetime, paid = unlimited while subscribed).
  * Square webhook signature verification and auto-downgrade on lapse.
"""
import base64
import hashlib
import hmac
import json
import types
import unittest
import uuid

import cherrypy
import pytest

from sfwebui import SpiderFootWebUi
from spiderfoot import SpiderFootDb
import spiderfoot.square_billing as square_billing


@pytest.mark.usefixtures
class TestBillingEnforcement(unittest.TestCase):
    """Test billing/plan enforcement and the Square webhook."""

    def _db(self):
        return SpiderFootDb(self.default_options, False)

    def _webui(self):
        opts = dict(self.default_options)
        opts['__modules__'] = dict()
        return SpiderFootWebUi(self.web_default_options, opts)

    def _new_user(self, plan=None, sub_id=None, cust_id=None, scans=0):
        db = self._db()
        email = f"{uuid.uuid4()}@example.com"
        uid = db.userCreate(email, "Test User")
        if plan:
            db.userUpdatePlan(uid, plan, cust_id or '', sub_id or '')
        for _ in range(scans):
            db.userIncrementScanCount(uid)
        return uid

    # ---- square_billing helpers -------------------------------------------

    def test_subscription_active(self):
        for status in ("ACTIVE", "PENDING", "active", "pending"):
            self.assertTrue(square_billing.subscription_active(status))
        for status in ("CANCELED", "DEACTIVATED", "PAUSED", "", None):
            self.assertFalse(square_billing.subscription_active(status))

    def test_verify_webhook_signature(self):
        key = "test-signature-key"
        url = "https://example.com/square_webhook"
        body = b'{"type":"subscription.updated"}'
        good = base64.b64encode(
            hmac.new(key.encode(), url.encode() + body, hashlib.sha256).digest()
        ).decode()

        saved = square_billing.WEBHOOK_SIGNATURE_KEY
        try:
            square_billing.WEBHOOK_SIGNATURE_KEY = key
            self.assertTrue(square_billing.verify_webhook_signature(good, body, url))
            self.assertFalse(square_billing.verify_webhook_signature("wrong", body, url))
            self.assertFalse(square_billing.verify_webhook_signature("", body, url))
            # Fails closed when no key is configured.
            square_billing.WEBHOOK_SIGNATURE_KEY = ""
            self.assertFalse(square_billing.verify_webhook_signature(good, body, url))
        finally:
            square_billing.WEBHOOK_SIGNATURE_KEY = saved

    # ---- db lookup ---------------------------------------------------------

    def test_userGetBySquareId_roundtrip(self):
        # The per-worker test DB persists across runs, so use unique ids.
        db = self._db()
        sub, cust = f"sub_{uuid.uuid4()}", f"cust_{uuid.uuid4()}"
        uid = self._new_user(plan="professional", sub_id=sub, cust_id=cust)

        by_sub = db.userGetBySquareId(subscription_id=sub)
        self.assertEqual(by_sub['id'], uid)
        by_cust = db.userGetBySquareId(customer_id=cust)
        self.assertEqual(by_cust['id'], uid)

        self.assertIsNone(db.userGetBySquareId(subscription_id=f"nope_{uuid.uuid4()}"))
        self.assertIsNone(db.userGetBySquareId())

    # ---- entitlement / quota ----------------------------------------------

    def test_userIsEntitled_matrix(self):
        self.assertFalse(SpiderFootWebUi._userIsEntitled({}))
        self.assertFalse(SpiderFootWebUi._userIsEntitled({'plan': 'free'}))
        # Paid but no active subscription id -> not entitled.
        self.assertFalse(SpiderFootWebUi._userIsEntitled({'plan': 'professional', 'sq_subscription_id': ''}))
        # Paid with an active subscription -> entitled.
        self.assertTrue(SpiderFootWebUi._userIsEntitled({'plan': 'professional', 'sq_subscription_id': 'sub_1'}))
        self.assertTrue(SpiderFootWebUi._userIsEntitled({'plan': 'agency', 'sq_subscription_id': 'sub_2'}))

    def test_scanQuotaExceeded(self):
        web = self._webui()

        # No session user (CLI/anonymous) is never limited.
        self.assertFalse(web._scanQuotaExceeded({}))

        free_fresh = self._new_user(scans=0)
        self.assertFalse(web._scanQuotaExceeded({'id': free_fresh}))

        free_used = self._new_user(scans=1)
        self.assertTrue(web._scanQuotaExceeded({'id': free_used}))

        # Paid + active subscription: unlimited even with many prior scans.
        paid = self._new_user(plan="professional", sub_id="sub_x", cust_id="cust_x", scans=5)
        self.assertFalse(web._scanQuotaExceeded({'id': paid}))

        # Paid plan but lapsed (no subscription id): treated as free.
        lapsed = self._new_user(plan="professional", sub_id="", cust_id="cust_y", scans=1)
        self.assertTrue(web._scanQuotaExceeded({'id': lapsed}))

    # ---- webhook handler ---------------------------------------------------

    def _fake_request(self, raw, signature="sig", method="POST"):
        cherrypy.request = types.SimpleNamespace(
            method=method,
            body=types.SimpleNamespace(read=lambda: raw),
            headers={'x-square-hmacsha256-signature': signature},
        )
        cherrypy.response = types.SimpleNamespace(status=None, headers={})

    def setUp(self):
        # cherrypy.request/response are real thread-local proxies; snapshot them
        # so the fakes below can be restored (deleting them breaks other tests).
        self._cp_saved = {a: getattr(cherrypy, a) for a in ("request", "response")
                          if hasattr(cherrypy, a)}

    def tearDown(self):
        for attr, value in self._cp_saved.items():
            setattr(cherrypy, attr, value)

    def test_webhook_downgrades_on_cancel(self):
        web = self._webui()
        db = self._db()
        sub, cust = f"sub_{uuid.uuid4()}", f"cust_{uuid.uuid4()}"
        uid = self._new_user(plan="professional", sub_id=sub, cust_id=cust)

        event = {
            "type": "subscription.updated",
            "data": {"type": "subscription", "object": {"subscription": {
                "id": sub, "status": "CANCELED", "customer_id": cust}}},
        }
        raw = json.dumps(event).encode()
        self._fake_request(raw)

        saved = square_billing.verify_webhook_signature
        try:
            square_billing.verify_webhook_signature = lambda *a, **k: True
            result = web.square_webhook()
        finally:
            square_billing.verify_webhook_signature = saved

        self.assertEqual(result, 'ok')
        after = db.userGetById(uid)
        self.assertEqual(after['plan'], 'free')
        self.assertFalse(after['sq_subscription_id'])

    def test_webhook_rejects_bad_signature(self):
        web = self._webui()
        db = self._db()
        sub = f"sub_{uuid.uuid4()}"
        uid = self._new_user(plan="professional", sub_id=sub, cust_id=f"cust_{uuid.uuid4()}")

        raw = json.dumps({"type": "subscription.updated", "data": {"object": {
            "subscription": {"id": sub, "status": "CANCELED"}}}}).encode()
        self._fake_request(raw, signature="bad")

        saved = square_billing.verify_webhook_signature
        try:
            square_billing.verify_webhook_signature = lambda *a, **k: False
            web.square_webhook()
        finally:
            square_billing.verify_webhook_signature = saved

        self.assertEqual(cherrypy.response.status, 401)
        # User must NOT be downgraded on an unverified event.
        self.assertEqual(db.userGetById(uid)['plan'], 'professional')

    def test_webhook_ignores_active_subscription(self):
        web = self._webui()
        db = self._db()
        sub = f"sub_{uuid.uuid4()}"
        uid = self._new_user(plan="professional", sub_id=sub, cust_id=f"cust_{uuid.uuid4()}")

        raw = json.dumps({"type": "subscription.updated", "data": {"object": {
            "subscription": {"id": sub, "status": "ACTIVE"}}}}).encode()
        self._fake_request(raw)

        saved = square_billing.verify_webhook_signature
        try:
            square_billing.verify_webhook_signature = lambda *a, **k: True
            web.square_webhook()
        finally:
            square_billing.verify_webhook_signature = saved

        # Still active -> plan unchanged.
        self.assertEqual(db.userGetById(uid)['plan'], 'professional')
