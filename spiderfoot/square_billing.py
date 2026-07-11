import os
import uuid
import hmac
import base64
import hashlib
import urllib.request
import urllib.error
import json

SQUARE_BASE = "https://connect.squareup.com/v2"
TOKEN = os.environ.get("SQUARE_ACCESS_TOKEN", "")
LOCATION_ID = os.environ.get("SQUARE_LOCATION_ID", "")
PLAN_IDS = {
    "professional": os.environ.get("SQUARE_PLAN_PROFESSIONAL", ""),
    "agency": os.environ.get("SQUARE_PLAN_AGENCY", ""),
}
WEBHOOK_SIGNATURE_KEY = os.environ.get("SQUARE_WEBHOOK_SIGNATURE_KEY", "")
WEBHOOK_URL = os.environ.get("SQUARE_WEBHOOK_URL", "")

# Square subscription statuses that still entitle a user to their paid plan.
ACTIVE_SUB_STATUSES = ("ACTIVE", "PENDING")


def verify_webhook_signature(signature: str, body: bytes, notification_url: str = None) -> bool:
    """Verify a Square webhook via HMAC-SHA256 over (notification_url + body).

    Fails closed: if the signature key or notification URL is not configured, or
    the signature is missing, verification fails so unverified events are ignored.

    Args:
        signature (str): value of the x-square-hmacsha256-signature header
        body (bytes): raw request body bytes
        notification_url (str): configured notification URL (defaults to env)

    Returns:
        bool: True if the signature is valid
    """
    key = WEBHOOK_SIGNATURE_KEY
    url = notification_url or WEBHOOK_URL
    if not key or not url or not signature:
        return False
    if isinstance(body, str):
        body = body.encode()
    digest = hmac.new(key.encode(), url.encode() + body, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, signature)


def subscription_active(status: str) -> bool:
    """Return True if a Square subscription status still grants entitlement.

    Args:
        status (str): Square subscription status (e.g. ACTIVE, CANCELED)

    Returns:
        bool: True if the status is one that keeps the plan active
    """
    return (status or "").upper() in ACTIVE_SUB_STATUSES


def _request(method: str, path: str, body: dict = None) -> dict:
    url = SQUARE_BASE + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Square-Version": "2024-02-22",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def create_customer(email: str, name: str) -> dict:
    parts = name.split(" ", 1)
    body = {
        "idempotency_key": str(uuid.uuid4()),
        "email_address": email,
        "given_name": parts[0],
        "family_name": parts[1] if len(parts) > 1 else "",
    }
    resp = _request("POST", "/customers", body)
    if "customer" in resp:
        return resp["customer"]
    raise RuntimeError(f"Square create_customer failed: {resp.get('errors')}")


def save_card(customer_id: str, nonce: str) -> str:
    """Save card on file, return card_id."""
    body = {
        "idempotency_key": str(uuid.uuid4()),
        "source_id": nonce,
        "card": {"customer_id": customer_id},
    }
    resp = _request("POST", "/cards", body)
    if "card" in resp:
        return resp["card"]["id"]
    raise RuntimeError(f"Square save_card failed: {resp.get('errors')}")


def create_subscription(customer_id: str, card_id: str, plan: str) -> dict:
    plan_id = PLAN_IDS.get(plan)
    if not plan_id:
        raise ValueError(f"Unknown plan: {plan}")
    body = {
        "idempotency_key": str(uuid.uuid4()),
        "location_id": LOCATION_ID,
        "plan_variation_id": plan_id,
        "customer_id": customer_id,
        "card_id": card_id,
    }
    resp = _request("POST", "/subscriptions", body)
    if "subscription" in resp:
        return resp["subscription"]
    raise RuntimeError(f"Square create_subscription failed: {resp.get('errors')}")


def cancel_subscription(subscription_id: str) -> bool:
    resp = _request("POST", f"/subscriptions/{subscription_id}/cancel")
    return "subscription" in resp


def get_subscription(subscription_id: str) -> dict:
    resp = _request("GET", f"/subscriptions/{subscription_id}")
    return resp.get("subscription", {})
