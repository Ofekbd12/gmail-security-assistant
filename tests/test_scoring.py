from backend.app.main import (
    calculate_final_score_from_breakdown,
    build_verdict_from_score,
    should_include_in_batch_report,
)


def make_risk_breakdown(
    sender=0,
    content=0,
    social=0,
    link=0,
    attachment=0,
):
    return {
        "sender_risk": {
            "score": sender,
            "max_score": 10,
            "explanation": "test sender risk",
        },
        "content_risk": {
            "score": content,
            "max_score": 10,
            "explanation": "test content risk",
        },
        "social_engineering_risk": {
            "score": social,
            "max_score": 10,
            "explanation": "test social engineering risk",
        },
        "link_risk": {
            "score": link,
            "max_score": 10,
            "explanation": "test link risk",
        },
        "attachment_risk": {
            "score": attachment,
            "max_score": 10,
            "explanation": "test attachment risk",
        },
    }


def test_safe_email_gets_minimum_score_one():
    risk_breakdown = make_risk_breakdown(
        sender=0,
        content=0,
        social=0,
        link=0,
        attachment=0,
    )

    assert calculate_final_score_from_breakdown(risk_breakdown) == 1


def test_high_sender_and_link_risk_affect_final_score():
    risk_breakdown = make_risk_breakdown(
        sender=10,
        content=0,
        social=0,
        link=10,
        attachment=0,
    )

    # 0.25*10 + 0.25*10 = 5
    assert calculate_final_score_from_breakdown(risk_breakdown) == 5


def test_mixed_risk_weighted_score():
    risk_breakdown = make_risk_breakdown(
        sender=6,
        content=7,
        social=8,
        link=9,
        attachment=0,
    )

    # 0.25*6 + 0.20*7 + 0.20*8 + 0.25*9 + 0.10*0
    # = 1.5 + 1.4 + 1.6 + 2.25 + 0 = 6.75 -> round = 7
    assert calculate_final_score_from_breakdown(risk_breakdown) == 7


def test_score_is_clamped_to_ten():
    risk_breakdown = make_risk_breakdown(
        sender=20,
        content=20,
        social=20,
        link=20,
        attachment=20,
    )

    assert calculate_final_score_from_breakdown(risk_breakdown) == 10


def test_verdict_mapping_safe():
    assert build_verdict_from_score(1) == "Safe"
    assert build_verdict_from_score(2) == "Safe"


def test_verdict_mapping_low_risk():
    assert build_verdict_from_score(3) == "Low Risk"
    assert build_verdict_from_score(4) == "Low Risk"


def test_verdict_mapping_suspicious():
    assert build_verdict_from_score(5) == "Suspicious"
    assert build_verdict_from_score(7) == "Suspicious"


def test_verdict_mapping_malicious():
    assert build_verdict_from_score(8) == "Malicious"
    assert build_verdict_from_score(10) == "Malicious"


def test_batch_report_excludes_score_three():
    assert should_include_in_batch_report(3, "Low Risk") is False


def test_batch_report_includes_score_above_three():
    assert should_include_in_batch_report(4, "Low Risk") is True


def test_batch_report_includes_suspicious_verdict():
    assert should_include_in_batch_report(2, "Suspicious") is True
    
def test_negative_category_scores_are_clamped_to_minimum_score_one():
    risk_breakdown = make_risk_breakdown(
        sender=-5,
        content=-3,
        social=-10,
        link=-2,
        attachment=-1,
    )

    assert calculate_final_score_from_breakdown(risk_breakdown) == 1