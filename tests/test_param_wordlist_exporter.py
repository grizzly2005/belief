from belief.exporters.param_wordlist import render_param_wordlist


def test_param_wordlist_includes_high_value_fields():
    text = render_param_wordlist()
    for word in ["is_admin", "tenant_id", "owner_id", "price", "balance", "permission"]:
        assert word in text.splitlines()


def test_param_wordlist_is_deterministic():
    assert render_param_wordlist(["zz_extra"]) == render_param_wordlist(["zz_extra"])
