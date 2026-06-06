"""Synthetic IDOR-style candidate: object mutation without visible owner guard."""


def update_account_display_name(request, account_store):
    account_id = request.params.get("account_id")
    account = account_store.get(account_id)
    if account is None:
        return {"status": "missing"}

    account["display_name"] = request.json.get("display_name", account["display_name"])
    return {"status": "updated", "account_id": account_id}
