import os
import uuid
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
