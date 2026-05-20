from backend.app.main import (
    add_deterministic_scoring_metadata,
    should_include_in_batch_report,
)


def test_malicious_email_analysis_becomes_malicious():
    fake_llm_analysis = {
        "summary": "This email appears to be a phishing attempt asking the user to verify account credentials.",
        "reasons": [
            "The sender domain appears to impersonate a known payment provider.",
            "The email creates urgency by threatening account suspension.",
            "The email asks the user to verify credentials through a suspicious link.",
            "The attachment name looks suspicious and may be executable.",
        ],
        "risk_breakdown": {
            "sender_risk": {
                "score": 9,
                "max_score": 10,
                "explanation": "The sender domain appears to impersonate a trusted brand.",
            },
            "content_risk": {
                "score": 8,
                "max_score": 10,
                "explanation": "The content asks for account verification and uses threatening language.",
            },
            "social_engineering_risk": {
                "score": 9,
                "max_score": 10,
                "explanation": "The email uses urgency and fear of account suspension.",
            },
            "link_risk": {
                "score": 10,
                "max_score": 10,
                "explanation": "The link points to a suspicious login page.",
            },
            "attachment_risk": {
                "score": 8,
                "max_score": 10,
                "explanation": "The attachment filename suggests a potentially executable file.",
            },
        },
        "recommended_actions": [
            "Do not click the link.",
            "Do not open the attachment.",
            "Verify the sender through an official website.",
            "Report or delete the email.",
        ],
    }

    result = add_deterministic_scoring_metadata(fake_llm_analysis)

    assert result["score"] >= 8
    assert result["verdict"] == "Malicious"
    assert result["display_label"] == "Malicious"
    assert result["severity_color"] == "red"
    assert result["should_warn"] is True


def test_safe_email_analysis_becomes_safe():
    fake_llm_analysis = {
        "summary": "This email appears to be a normal personal message with no suspicious indicators.",
        "reasons": [
            "The sender appears normal.",
            "There are no suspicious links.",
            "There are no requests for sensitive information.",
        ],
        "risk_breakdown": {
            "sender_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No sender risk detected.",
            },
            "content_risk": {
                "score": 1,
                "max_score": 10,
                "explanation": "The content appears normal.",
            },
            "social_engineering_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No pressure or manipulation detected.",
            },
            "link_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No suspicious links detected.",
            },
            "attachment_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No attachments detected.",
            },
        },
        "recommended_actions": [
            "No immediate action required.",
        ],
    }

    result = add_deterministic_scoring_metadata(fake_llm_analysis)

    assert result["score"] <= 2
    assert result["verdict"] == "Safe"
    assert result["display_label"] == "Safe"
    assert result["severity_color"] == "green"
    assert result["should_warn"] is False


def test_batch_scan_includes_malicious_email():
    assert should_include_in_batch_report(9, "Malicious") is True


def test_batch_scan_excludes_safe_email():
    assert should_include_in_batch_report(2, "Safe") is False
    
def test_suspicious_email_analysis_becomes_suspicious_mid_range():
    fake_llm_analysis = {
        "summary": "This email has some suspicious indicators but does not appear clearly malicious.",
        "reasons": [
            "The sender is unfamiliar.",
            "The message asks the user to review an account-related issue.",
            "The wording creates mild urgency but does not directly demand credentials.",
            "There is a link, but no attachment was detected.",
        ],
        "risk_breakdown": {
            "sender_risk": {
                "score": 5,
                "max_score": 10,
                "explanation": "The sender is unfamiliar but not clearly spoofed.",
            },
            "content_risk": {
                "score": 5,
                "max_score": 10,
                "explanation": "The content asks the user to review an account-related issue.",
            },
            "social_engineering_risk": {
                "score": 6,
                "max_score": 10,
                "explanation": "The email creates some urgency but does not use extreme pressure.",
            },
            "link_risk": {
                "score": 5,
                "max_score": 10,
                "explanation": "A link is present and should be reviewed before clicking.",
            },
            "attachment_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No attachment was detected.",
            },
        },
        "recommended_actions": [
            "Review the sender carefully.",
            "Do not click the link unless the sender is verified.",
            "Open the official website manually if account action is needed.",
        ],
    }

    result = add_deterministic_scoring_metadata(fake_llm_analysis)

    assert result["score"] == 5
    assert result["verdict"] == "Suspicious"
    assert result["display_label"] == "Suspicious"
    assert result["severity_color"] == "orange"
    assert result["should_warn"] is True
    
def test_missing_risk_category_is_treated_as_zero():
    fake_llm_analysis = {
        "summary": "This email has limited risk indicators.",
        "reasons": [
            "The email contains mild uncertainty.",
        ],
        "risk_breakdown": {
            "sender_risk": {
                "score": 4,
                "max_score": 10,
                "explanation": "Sender is somewhat unfamiliar.",
            },
            "content_risk": {
                "score": 4,
                "max_score": 10,
                "explanation": "Content has minor uncertainty.",
            },
            "social_engineering_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No social engineering detected.",
            },
            "link_risk": {
                "score": 0,
                "max_score": 10,
                "explanation": "No links detected.",
            },
            # attachment_risk is intentionally missing
        },
        "recommended_actions": [
            "Review carefully if unexpected.",
        ],
    }

    result = add_deterministic_scoring_metadata(fake_llm_analysis)

    assert result["score"] == 2
    assert result["verdict"] == "Safe"
    assert result["display_label"] == "Safe"
    assert result["severity_color"] == "green"
    assert result["should_warn"] is False


def test_batch_threshold_exact_boundary():
    assert should_include_in_batch_report(3, "Low Risk") is False
    assert should_include_in_batch_report(4, "Low Risk") is True