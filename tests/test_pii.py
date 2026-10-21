from guardrails.pii import find_pii, redact_pii


def test_ssn_detected_and_redacted():
    redacted, entities = redact_pii("My SSN is 123-45-6789 please.")
    assert "[REDACTED_SSN]" in redacted and "123-45-6789" not in redacted
    assert any(e.type == "SSN" for e in entities)


def test_email_and_api_key():
    types = {e.type for e in find_pii("mail alice@example.com key sk-abcdefghij1234567890")}
    assert "EMAIL" in types and "API_KEY" in types


def test_aws_key_and_card():
    types = {e.type for e in find_pii("AKIAIOSFODNN7EXAMPLE card 4111-1111-1111-1111")}
    assert "AWS_ACCESS_KEY" in types and "CREDIT_CARD" in types


def test_clean_text_has_no_pii():
    assert find_pii("Explain RBAC in one sentence.") == []


def test_invalid_card_not_flagged():
    assert not any(e.type == "CREDIT_CARD" for e in find_pii("order 1234-5678-9012-3456"))
