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
        "Backend service for analyzing a user-selected email "
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


def add_ui_metadata(analysis: dict) -> dict:
    """
    Adds UI-oriented metadata to the LLM analysis result.

    The Gmail add-on uses these fields to decide:
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