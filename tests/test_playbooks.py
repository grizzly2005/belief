from belief.reportability.playbooks import playbook_for_category


def test_idor_playbook_uses_user_a_user_b_validation():
    steps = playbook_for_category("idor_bola_possible")
    text = " ".join(steps)

    assert "User A" in text
    assert "User B" in text
    assert "Expected secure behavior" in text


def test_mass_assignment_playbook_mentions_sensitive_fields_without_payloads():
    steps = playbook_for_category("mass_assignment")
    text = " ".join(steps).lower()

    assert "is_admin" in text
    assert "tenant_id" in text
    assert "curl " not in text
    assert "<script" not in text


def test_path_traversal_playbook_discusses_boundaries_safely():
    text = " ".join(playbook_for_category("path_traversal")).lower()

    assert "base-directory boundary" in text
    assert "candidate becomes reportable only" in text


def test_deserialization_playbook_discusses_trusted_source_and_signing():
    text = " ".join(playbook_for_category("unsafe_deserialization")).lower()

    assert "signing" in text
    assert "trusted-source" in text or "trusted-source guarantees" in text
