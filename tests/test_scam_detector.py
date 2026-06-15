from scam_detector import analyze_text


def test_clean_message_has_no_flags():
    result = analyze_text("Hey, are we still meeting for lunch tomorrow?")
    assert result.score == 0
    assert result.risk_level == "none"
    assert result.reasons == []


def test_lottery_scam_is_flagged():
    result = analyze_text(
        "Congratulations! You've won a free gift. Click here to claim your prize now!"
    )
    assert result.score > 0
    assert "prize or lottery claim" in result.reasons


def test_bank_phishing_is_high_risk():
    text = (
        "URGENT: Your bank account has been suspended. "
        "Verify your identity immediately by clicking the link below: bit.ly/abc123"
    )
    result = analyze_text(text)
    assert result.risk_level == "high"
    assert "urgency language" in result.reasons
    assert "requests personal/financial info" in result.reasons
    assert "suspicious shortened or odd links" in result.reasons


def test_gift_card_request_is_flagged():
    result = analyze_text("Please purchase a $200 Google Play card and send me the code.")
    assert "requests payment via gift cards or crypto" in result.reasons
