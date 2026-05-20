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
        "Backend service for analyzing user-selected emails "
        "using LLM-based phishing and malicious-risk scoring."
    ),
    version="1.0.0",
)


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    links: list[str] = []
    attachments: list[str] = []


class RiskCategory(BaseModel):
    score: int
    max_score: int
    explanation: str


class RiskBreakdown(BaseModel):
    sender_risk: RiskCategory
    content_risk: RiskCategory
    social_engineering_risk: RiskCategory
    link_risk: RiskCategory
    attachment_risk: RiskCategory


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


class BatchEmailScanRequest(BaseModel):
    emails: list[EmailRequest]


class BatchEmailSummary(BaseModel):
    email_index: int
    sender: str
    subject: str
    score: int
    verdict: str
    summary: str
    reasons: list[str]
    recommended_actions: list[str]
    should_warn: bool
    severity_color: str
    display_label: str


class BatchEmailScanResponse(BaseModel):
    emails_analyzed: int
    risky_emails_found: bool
    risky_emails_count: int
    risky_emails: list[BatchEmailSummary]


@app.get("/")
def home():
    return {"message": "Backend is running"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(email: EmailRequest):
    """
    Manual scan flow:
    The user opens a specific email and clicks 'Scan Current Email'.
    The backend returns a full risk analysis for that selected email.
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


@app.post("/analyze-email-batch", response_model=BatchEmailScanResponse)
def analyze_email_batch(request: BatchEmailScanRequest):
    """
    User-controlled batch scan flow:
    The user adds selected emails to the scan queue.
    The backend analyzes the selected emails in one LLM call.
    Only emails with score > 3, or meaningful suspicious verdicts,
    are returned in the report.
    """
    try:
        if not request.emails:
            return {
                "emails_analyzed": 0,
                "risky_emails_found": False,
                "risky_emails_count": 0,
                "risky_emails": [],
            }

        batch_result = analyze_batch_emails_with_llm(request.emails)
        risky_emails = []

        for item in batch_result.get("risky_emails", []):
            email_index = item.get("email_index")

            if email_index is None:
                continue

            if email_index < 0 or email_index >= len(request.emails):
                continue

            original_email = request.emails[email_index]

            score = int(item.get("score", 1))
            verdict = item.get("verdict", "Suspicious")

            if not should_include_in_batch_report(score, verdict):
                continue

            ui_metadata = build_ui_metadata(score, verdict)

            risky_emails.append(
                {
                    "email_index": email_index,
                    "sender": original_email.sender,
                    "subject": original_email.subject,
                    "score": score,
                    "verdict": verdict,
                    "summary": item.get(
                        "summary",
                        "This email may require attention."
                    ),
                    "reasons": item.get(
                        "reasons",
                        ["This email matched suspicious risk indicators."]
                    ),
                    "recommended_actions": item.get(
                        "recommended_actions",
                        ["Review this email carefully before taking action."]
                    ),
                    "should_warn": ui_metadata["should_warn"],
                    "severity_color": ui_metadata["severity_color"],
                    "display_label": ui_metadata["display_label"],
                }
            )

        return {
            "emails_analyzed": len(request.emails),
            "risky_emails_found": len(risky_emails) > 0,
            "risky_emails_count": len(risky_emails),
            "risky_emails": risky_emails,
        }

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="LLM returned an invalid JSON response."
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Batch email analysis failed: {str(error)}"
        )


def should_include_in_batch_report(score: int, verdict: str) -> bool:
    """
    Batch scan should return only emails that require user attention.
    Minimum inclusion threshold: score > 3.
    """
    risky_verdicts = ["Suspicious", "High Risk", "Malicious"]

    return score > 3 or verdict in risky_verdicts


def add_ui_metadata(analysis: dict) -> dict:
    """
    Adds UI-oriented metadata to the LLM analysis result.
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
    Removes markdown wrapping if needed.
    """
    cleaned_text = raw_text.strip()

    if cleaned_text.startswith("```json"):
        cleaned_text = cleaned_text.replace("```json", "", 1).strip()

    if cleaned_text.startswith("```"):
        cleaned_text = cleaned_text.replace("```", "", 1).strip()

    if cleaned_text.endswith("```"):
        cleaned_text = cleaned_text[:-3].strip()

    return json.loads(cleaned_text)


def analyze_batch_emails_with_llm(emails: list[EmailRequest]):
    """
    Lightweight batch analysis for user-selected scan queue.

    This function sends all selected emails to the LLM in one call.
    It asks the LLM to return only emails with score > 3 or meaningful risk.
    """
    email_items = []

    for index, email in enumerate(emails):
        email_items.append(
            {
                "email_index": index,
                "sender": email.sender,
                "subject": email.subject,
                "body": email.body[:1500],
                "links": email.links,
                "attachments": email.attachments,
            }
        )

    prompt = f"""
You are an email security assistant integrated into Gmail.

You are performing a user-controlled Scan Queue analysis.

The user selected several emails for analysis.
Your goal is to review the selected emails and return ONLY emails that require
user attention.

Do not return clearly safe emails.

Minimum inclusion threshold:
- Include an email only if score > 3.
- Also include emails with verdict "Suspicious", "High Risk", or "Malicious".
- Do not include clearly safe emails.
- Low-risk emails should only be included if they still require user attention.

Evaluate each email according to:
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
- score must be an integer from 1 to 10.
- 1 means clearly safe.
- 10 means clearly malicious.
- Be strict with suspicious links, credential requests, fake domains,
  and dangerous attachments.
- Do not exaggerate risk without concrete indicators.

Return ONLY valid JSON in this exact structure:

{{
  "risky_emails": [
    {{
      "email_index": 0,
      "score": 4,
      "verdict": "Suspicious",
      "summary": "short explanation of why this email requires attention",
      "reasons": [
        "reason 1",
        "reason 2"
      ],
      "recommended_actions": [
        "action 1",
        "action 2"
      ]
    }}
  ]
}}

Allowed verdict values:
- Suspicious
- High Risk
- Malicious

If there are no risky emails, return:

{{
  "risky_emails": []
}}

Emails:
{json.dumps(email_items, ensure_ascii=False)}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt
    )

    raw_text = response.output_text

    return parse_llm_json(raw_text)


def analyze_single_email_with_llm(email: EmailRequest):
    prompt = f"""
You are an email security assistant integrated into Gmail.

Analyze the following email and determine whether it looks safe, suspicious,
or malicious.

This analysis is used for Manual Email Scan:
The user explicitly chooses "Scan Current Email" on a specific opened email.
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
- Overall score must be an integer from 1 to 10.
- 1 means clearly safe.
- 10 means clearly malicious.
- Be strict with suspicious links, credential requests, fake domains,
  and dangerous attachments.
- Do not exaggerate risk if there are no concrete indicators.
- The score should be based only on the actual risk indicators
  found in the email.

Risk breakdown instructions:
- Each risk_breakdown category must include:
  - score: integer from 0 to 10
  - max_score: always 10
  - explanation: short explanation for that category score
- If a category has no meaningful risk indicators, use score 0 and explain
  that no relevant risk was detected.
- The category explanations should be clear enough to show in a
  "View Detailed Breakdown" screen inside the Gmail add-on.

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
    "sender_risk": {{
      "score": 0,
      "max_score": 10,
      "explanation": "short explanation"
    }},
    "content_risk": {{
      "score": 0,
      "max_score": 10,
      "explanation": "short explanation"
    }},
    "social_engineering_risk": {{
      "score": 0,
      "max_score": 10,
      "explanation": "short explanation"
    }},
    "link_risk": {{
      "score": 0,
      "max_score": 10,
      "explanation": "short explanation"
    }},
    "attachment_risk": {{
      "score": 0,
      "max_score": 10,
      "explanation": "short explanation"
    }}
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