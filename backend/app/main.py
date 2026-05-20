from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI
import os
import json


load_dotenv(override=True)

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError(
        "OPENAI_API_KEY is missing. Please set it in the .env file."
    )

client = OpenAI(api_key=api_key)

app = FastAPI(
    title="Gmail Security Assistant API",
    description=(
        "Backend service for analyzing suspicious emails "
        "using LLM-based risk scoring."
    ),
    version="1.0.0",
)


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    links: list[str] = []
    attachments: list[str] = []


class RiskBreakdown(BaseModel):
    sender_risk: int
    content_risk: int
    social_engineering_risk: int
    link_risk: int
    attachment_risk: int


class EmailAnalysisResponse(BaseModel):
    score: int
    verdict: str
    summary: str
    reasons: list[str]
    risk_breakdown: RiskBreakdown
    recommended_actions: list[str]
    should_warn: bool
    severity_color: str
    display_label: str


class InitialInboxScanRequest(BaseModel):
    emails: list[EmailRequest]


class SuspiciousEmailSummary(BaseModel):
    sender: str
    subject: str
    score: int
    verdict: str
    summary: str
    recommended_actions: list[str]
    should_warn: bool
    severity_color: str
    display_label: str


class InitialInboxScanResponse(BaseModel):
    suspicious_emails_found: bool
    total_emails_scanned: int
    suspicious_emails_count: int
    suspicious_emails: list[SuspiciousEmailSummary]


@app.get("/")
def home():
    return {"message": "Backend is running"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(email: EmailRequest):
    """
    Manual scan flow:
    The user opens a specific email and clicks 'Scan Email'.
    The backend returns a full risk analysis for that email.
    """
    try:
        analysis = analyze_single_email_with_llm(email)
        analysis_with_ui = add_ui_metadata(analysis)
        return analysis_with_ui

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="LLM returned an invalid JSON response."
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(error)}"
        )


@app.post("/initial-inbox-scan", response_model=InitialInboxScanResponse)
def initial_inbox_scan(request: InitialInboxScanRequest):
    """
    Initial inbox scan flow:
    When the user opens the Gmail add-on, the system scans recent,
    unread, or newly received emails and returns only risky emails
    that should appear in the initial security summary report.
    """
    try:
        suspicious_emails = []

        for email in request.emails:
            analysis = analyze_single_email_with_llm(email)
            analysis_with_ui = add_ui_metadata(analysis)

            if should_include_in_security_report(analysis_with_ui):
                suspicious_emails.append(
                    {
                        "sender": email.sender,
                        "subject": email.subject,
                        "score": analysis_with_ui["score"],
                        "verdict": analysis_with_ui["verdict"],
                        "summary": analysis_with_ui["summary"],
                        "recommended_actions": analysis_with_ui[
                            "recommended_actions"
                        ],
                        "should_warn": analysis_with_ui["should_warn"],
                        "severity_color": analysis_with_ui["severity_color"],
                        "display_label": analysis_with_ui["display_label"],
                    }
                )

        return {
            "suspicious_emails_found": len(suspicious_emails) > 0,
            "total_emails_scanned": len(request.emails),
            "suspicious_emails_count": len(suspicious_emails),
            "suspicious_emails": suspicious_emails,
        }

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="LLM returned an invalid JSON response."
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Initial inbox scan failed: {str(error)}"
        )


def should_include_in_security_report(analysis: dict) -> bool:
    """
    Decides whether an email should appear in the initial warning report.
    This keeps the initial report focused only on meaningful risks.
    """
    score = analysis.get("score", 1)
    verdict = analysis.get("verdict", "Safe")
    should_warn = analysis.get("should_warn", False)

    risky_verdicts = ["Suspicious", "High Risk", "Malicious"]

    return should_warn or score >= 5 or verdict in risky_verdicts


def add_ui_metadata(analysis: dict) -> dict:
    """
    Adds UI-oriented metadata to the LLM analysis result.

    The Gmail add-on can use these fields to decide:
    - whether to show a warning
    - which severity color to display
    - which short label to show to the user
    """
    score = analysis.get("score", 1)
    verdict = analysis.get("verdict", "Safe")

    ui_metadata = build_ui_metadata(score, verdict)

    return {
        **analysis,
        **ui_metadata,
    }


def build_ui_metadata(score: int, verdict: str) -> dict:
    """
    Converts risk score and verdict into simple UI display decisions.
    """
    if score >= 8 or verdict == "Malicious":
        return {
            "should_warn": True,
            "severity_color": "red",
            "display_label": "Malicious",
        }

    if score >= 5 or verdict in ["Suspicious", "High Risk"]:
        return {
            "should_warn": True,
            "severity_color": "orange",
            "display_label": "Suspicious",
        }

    if score >= 3 or verdict == "Low Risk":
        return {
            "should_warn": False,
            "severity_color": "yellow",
            "display_label": "Low Risk",
        }

    return {
        "should_warn": False,
        "severity_color": "green",
        "display_label": "Safe",
    }


def parse_llm_json(raw_text: str):
    """
    Converts the LLM response into JSON.

    Sometimes the LLM may wrap the JSON in markdown, for example:
    ```json
    { ... }
    ```

    This function removes that wrapping before parsing.
    """
    cleaned_text = raw_text.strip()

    if cleaned_text.startswith("```json"):
        cleaned_text = cleaned_text.replace("```json", "", 1).strip()

    if cleaned_text.startswith("```"):
        cleaned_text = cleaned_text.replace("```", "", 1).strip()

    if cleaned_text.endswith("```"):
        cleaned_text = cleaned_text[:-3].strip()

    return json.loads(cleaned_text)


def analyze_single_email_with_llm(email: EmailRequest):
    prompt = f"""
You are an email security assistant integrated into Gmail.

Analyze the following email and determine whether it looks safe, suspicious,
or malicious.

This analysis may be used in two product flows:
1. Initial Inbox Scan:
   The system scans recent, unread, or newly received emails when the user
   opens the Gmail add-on. Risky emails should appear in a security summary.
2. Manual Email Scan:
   The user explicitly chooses "Scan Email" on a specific opened email.
   The result should help the user understand whether the email is risky.

Evaluate the email according to these criteria:
1. Sender identity and possible impersonation
2. Subject line
3. Message body
4. Urgency or pressure tactics
5. Requests for passwords, login, payment, verification, MFA codes,
   or personal data
6. Social engineering patterns
7. Suspicious links
8. Suspicious attachments
9. Overall phishing or malicious intent

Scoring instructions:
- Score must be an integer from 1 to 10.
- 1 means clearly safe.
- 10 means clearly malicious.
- Be strict with suspicious links, credential requests, fake domains,
  and dangerous attachments.
- Do not exaggerate risk if there are no concrete indicators.
- The score should be based only on the actual risk indicators
  found in the email.

Return ONLY valid JSON in this exact structure:

{{
  "score": 1,
  "verdict": "Safe",
  "summary": "short explanation in one sentence",
  "reasons": [
    "reason 1",
    "reason 2"
  ],
  "risk_breakdown": {{
    "sender_risk": 0,
    "content_risk": 0,
    "social_engineering_risk": 0,
    "link_risk": 0,
    "attachment_risk": 0
  }},
  "recommended_actions": [
    "action 1",
    "action 2"
  ]
}}

Allowed verdict values:
- Safe
- Low Risk
- Suspicious
- High Risk
- Malicious

Email:
Sender: {email.sender}
Subject: {email.subject}
Body: {email.body}
Links: {email.links}
Attachments: {email.attachments}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    raw_text = response.output_text

    return parse_llm_json(raw_text)