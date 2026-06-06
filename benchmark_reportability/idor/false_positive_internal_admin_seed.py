"""Synthetic likely false-positive: internal seed helper, not request-controlled."""


def seed_internal_demo_account(account_store):
    demo_account_id = "demo-account"
    account_store[demo_account_id] = {
        "owner_id": "internal-seed",
        "display_name": "Demo Account",
    }
    return demo_account_id
