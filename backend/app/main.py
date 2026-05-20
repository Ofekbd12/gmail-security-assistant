from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from openai import OpenAI
import os
import json
import logging


load_dotenv(override=True)

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise RuntimeError(
        "OPENAI_API_KEY is missing. Please set it in the .env file."
    )

client = OpenAI(api_key=api_key)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("gmail-security-assistant")

app = FastAPI(
    title="Gmail Security Assistant API",
    description=(
        "Backend service for analyzing suspicious emails using "
        "LLM-based risk analysis and deterministic backend scoring."
    ),
    version="1.0.0",
)


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    links: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)


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


class BatchEmailAnalysisRequest(BaseModel):
    emails: list[EmailRequest]


class RiskyEmailSummary(BaseModel):
    email_index: int
    sender: str
    subject: str
    score: int
    verdict: str
    summary: str
    recommended_actions: list[str]
    should_warn: bool
    severity_color: str
    display_label: str


class BatchEmailAnalysisResponse(BaseModel):
    emails_analyzed: int
    risky_emails_found: bool
    risky_emails_count: int
    risky_emails: list[RiskyEmailSummary]


@app.get("/")
def home():
    return {"message": "Backend is running"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze_email(email: EmailRequest):
    """
    Manual scan flow:
    The user opens a specific email and clicks "Scan Current Email".
    The backend returns a full detailed risk analysis for that email.
    """
    logger.info(
        "Single email analysis started | sender=%s | subject_length=%s | body_length=%s | links=%s | attachments=%s",
        sanitize_text(email.sender),
        len(email.subject or ""),
        len(email.body or ""),
        len(email.links),
        len(email.attachments),
    )

    try:
        analysis = analyze_single_email_with_llm(email)
        analysis_with_metadata = add_deterministic_scoring_metadata(analysis)

        logger.info(
            "Single email analysis completed | sender=%s | score=%s | verdict=%s | should_warn=%s",
            sanitize_text(email.sender),
            analysis_with_metadata.get("score"),
            analysis_with_metadata.get("verdict"),
            analysis_with_metadata.get("should_warn"),
        )

        return analysis_with_metadata

    except json.JSONDecodeError:
        logger.exception(
            "Single email analysis failed because the LLM returned invalid JSON | sender=%s",
            sanitize_text(email.sender),
        )

        raise HTTPException(
            status_code=500,
            detail="LLM returned an invalid JSON response.",
        )

    except Exception as error:
        logger.exception(
            "Single email analysis failed | sender=%s | error=%s",
            sanitize_text(email.sender),
            str(error),
        )

        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(error)}",
        )


@app.post("/analyze-email-batch", response_model=BatchEmailAnalysisResponse)
def analyze_email_batch(request: BatchEmailAnalysisRequest):
    """
    Batch scan flow:
    The user adds selected emails to the Scan Queue and clicks
    "Scan Selected Emails".

    The backend analyzes all selected emails in one LLM call and returns only
    emails whose deterministic final score is greater than 3.
    """
    logger.info(
        "Batch email analysis started | emails_count=%s",
        len(request.emails),
    )

    try:
        if not request.emails:
            logger.info("Batch email analysis skipped | emails_count=0")

            return {
                "emails_analyzed": 0,
                "risky_emails_found": False,
                "risky_emails_count": 0,
                "risky_emails": [],
            }

        batch_result = analyze_batch_emails_with_llm(request.emails)
        risky_emails = []

        for item in batch_result.get("emails", []):
            email_index = item.get("email_index")

            if email_index is None:
                continue

            if email_index < 0 or email_index >= len(request.emails):
                continue

            original_email = request.emails[email_index]

            analysis = normalize_llm_analysis(item)
            analysis_with_metadata = add_deterministic_scoring_metadata(
                analysis
            )

            score = analysis_with_metadata["score"]
            verdict = analysis_with_metadata["verdict"]

            if not should_include_in_batch_report(score, verdict):
                continue

            risky_emails.append(
                {
                    "email_index": email_index,
                    "sender": sanitize_text(original_email.sender),
                    "subject": sanitize_text(original_email.subject),
                    "score": score,
                    "verdict": verdict,
                    "summary": analysis_with_metadata["summary"],
                    "recommended_actions": analysis_with_metadata[
                        "recommended_actions"
                    ],
                    "should_warn": analysis_with_metadata["should_warn"],
                    "severity_color": analysis_with_metadata[
                        "severity_color"
                    ],
                    "display_label": analysis_with_metadata[
                        "display_label"
                    ],
                }
            )

        logger.info(
            "Batch email analysis completed | emails_analyzed=%s | risky_emails_count=%s",
            len(request.emails),
            len(risky_emails),
        )

        return {
            "emails_analyzed": len(request.emails),
            "risky_emails_found": len(risky_emails) > 0,
            "risky_emails_count": len(risky_emails),
            "risky_emails": risky_emails,
        }

    except json.JSONDecodeError:
        logger.exception(
            "Batch email analysis failed because the LLM returned invalid JSON | emails_count=%s",
            len(request.emails),
        )

        raise HTTPException(
            status_code=500,
            detail="LLM returned an invalid JSON response.",
        )

    except Exception as error:
        logger.exception(
            "Batch email analysis failed | emails_count=%s | error=%s",
            len(request.emails),
            str(error),
        )

        raise HTTPException(
            status_code=500,
            detail=f"Batch email analysis failed: {str(error)}",
        )


def sanitize_text(value) -> str:
    """
    Removes invalid Unicode surrogate characters that may appear in Gmail
    message bodies or subjects and break UTF-8 encoding.
    """
    if value is None:
        return ""

    text = str(value)

    return (
        text.encode("utf-8", errors="ignore")
        .decode("utf-8", errors="ignore")
    )


def sanitize_email(email: EmailRequest) -> dict:
    """
    Sanitizes all email fields before sending them to the LLM.
    """
    return {
        "sender": sanitize_text(email.sender),
        "subject": sanitize_text(email.subject),
        "body": sanitize_text(email.body),
        "links": [sanitize_text(link) for link in email.links],
        "attachments": [
            sanitize_text(attachment) for attachment in email.attachments
        ],
    }


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def get_category_score(risk_breakdown: dict, category_name: str) -> int:
    """
    Safely extracts a category score from the LLM risk breakdown.
    Missing or invalid categories are treated as zero.
    """
    category = risk_breakdown.get(category_name, {})

    try:
        score = int(category.get("score", 0))
    except (TypeError, ValueError):
        score = 0

    return clamp(score, 0, 10)


def calculate_final_score_from_breakdown(risk_breakdown: dict) -> int:
    """
    Calculates the final risk score using deterministic backend logic.

    Weights:
    - Sender Risk: 25%
    - Content Risk: 20%
    - Social Engineering Risk: 20%
    - Link Risk: 25%
    - Attachment Risk: 10%
    """
    sender_score = get_category_score(risk_breakdown, "sender_risk")
    content_score = get_category_score(risk_breakdown, "content_risk")
    social_score = get_category_score(
        risk_breakdown,
        "social_engineering_risk",
    )
    link_score = get_category_score(risk_breakdown, "link_risk")
    attachment_score = get_category_score(
        risk_breakdown,
        "attachment_risk",
    )

    weighted_score = (
        0.25 * sender_score
        + 0.20 * content_score
        + 0.20 * social_score
        + 0.25 * link_score
        + 0.10 * attachment_score
    )

    final_score = round(weighted_score)

    return clamp(final_score, 1, 10)


def build_verdict_from_score(score: int) -> str:
    """
    Maps the deterministic final score to a user-facing verdict.
    """
    if score >= 8:
        return "Malicious"

    if score >= 5:
        return "Suspicious"

    if score >= 3:
        return "Low Risk"

    return "Safe"


def build_ui_metadata(score: int, verdict: str) -> dict:
    """
    Converts score and verdict into UI display metadata.
    """
    if verdict == "Malicious":
        return {
            "should_warn": True,
            "severity_color": "red",
            "display_label": "Malicious",
        }

    if verdict == "Suspicious":
        return {
            "should_warn": True,
            "severity_color": "orange",
            "display_label": "Suspicious",
        }

    if verdict == "Low Risk":
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


def should_include_in_batch_report(score: int, verdict: str) -> bool:
    """
    Batch reports should include only emails that require attention.

    Current project decision:
    show only emails whose final deterministic score is greater than 3.
    """
    return score > 3


def build_default_risk_category(explanation: str = "No relevant risk detected.") -> dict:
    return {
        "score": 0,
        "max_score": 10,
        "explanation": explanation,
    }


def normalize_risk_breakdown(risk_breakdown: dict) -> dict:
    """
    Ensures the risk breakdown includes all required categories.
    Missing categories are filled with score 0.
    """
    if not isinstance(risk_breakdown, dict):
        risk_breakdown = {}

    return {
        "sender_risk": risk_breakdown.get(
            "sender_risk",
            build_default_risk_category("No sender risk detected."),
        ),
        "content_risk": risk_breakdown.get(
            "content_risk",
            build_default_risk_category("No content risk detected."),
        ),
        "social_engineering_risk": risk_breakdown.get(
            "social_engineering_risk",
            build_default_risk_category(
                "No social engineering risk detected."
            ),
        ),
        "link_risk": risk_breakdown.get(
            "link_risk",
            build_default_risk_category("No link risk detected."),
        ),
        "attachment_risk": risk_breakdown.get(
            "attachment_risk",
            build_default_risk_category("No attachment risk detected."),
        ),
    }


def normalize_llm_analysis(analysis: dict) -> dict:
    """
    Normalizes LLM output so the backend response remains stable even if
    optional fields are missing.
    """
    normalized_risk_breakdown = normalize_risk_breakdown(
        analysis.get("risk_breakdown", {})
    )

    return {
        "summary": analysis.get(
            "summary",
            "The email was analyzed for security risk indicators.",
        ),
        "reasons": analysis.get(
            "reasons",
            ["No detailed reasons were provided."],
        ),
        "risk_breakdown": normalized_risk_breakdown,
        "recommended_actions": analysis.get(
            "recommended_actions",
            ["Review this email carefully before taking action."],
        ),
    }


def add_deterministic_scoring_metadata(analysis: dict) -> dict:
    """
    Adds deterministic backend scoring and UI metadata to the LLM analysis.
    """
    normalized_analysis = normalize_llm_analysis(analysis)

    final_score = calculate_final_score_from_breakdown(
        normalized_analysis["risk_breakdown"]
    )

    verdict = build_verdict_from_score(final_score)
    ui_metadata = build_ui_metadata(final_score, verdict)

    logger.info(
        "Deterministic score calculated | score=%s | verdict=%s",
        final_score,
        verdict,
    )

    return {
        **normalized_analysis,
        "score": final_score,
        "verdict": verdict,
        **ui_metadata,
    }


def parse_llm_json(raw_text: str):
    """
    Converts the LLM response into JSON.
    Removes markdown code fences if needed.
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
    sanitized_email = sanitize_email(email)

    prompt = f"""
You are an email security assistant integrated into Gmail.

Analyze the following email and determine whether it contains security risk
indicators such as phishing, impersonation, social engineering, malicious links,
or suspicious attachments.

Important:
- Return only valid JSON.
- Do not include markdown.
- Do not include text before or after the JSON.
- The final score and verdict will be calculated by the backend.
- Your task is to provide category-level risk scores and explanations.

Evaluate the email according to these criteria:
1. Sender identity and possible impersonation
2. Subject line
3. Message body
4. Urgency or pressure tactics
5. Requests for passwords, login, payment, MFA codes, or personal data
6. Social engineering patterns
7. Suspicious links
8. Suspicious attachments
9. Overall phishing or malicious intent

Risk breakdown instructions:
- Each risk_breakdown category must include:
  - score: integer from 0 to 10
  - max_score: always 10
  - explanation: short explanation for that category score
- If a category has no meaningful risk indicators, use score 0 and explain
  that no relevant risk was detected.

Return ONLY valid JSON in this exact structure:

{{
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

Email:
Sender: {sanitized_email["sender"]}
Subject: {sanitized_email["subject"]}
Body: {sanitized_email["body"]}
Links: {sanitized_email["links"]}
Attachments: {sanitized_email["attachments"]}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    raw_text = response.output_text

    return parse_llm_json(raw_text)


def analyze_batch_emails_with_llm(emails: list[EmailRequest]):
    email_items = []

    for index, email in enumerate(emails):
        sanitized_email = sanitize_email(email)

        email_items.append(
            {
                "email_index": index,
                "sender": sanitized_email["sender"],
                "subject": sanitized_email["subject"],
                "body": sanitized_email["body"][:1500],
                "links": sanitized_email["links"],
                "attachments": sanitized_email["attachments"],
            }
        )

    prompt = f"""
You are an email security assistant integrated into Gmail.

You are performing a batch scan of user-selected emails from a Scan Queue.

Important:
- Return only valid JSON.
- Do not include markdown.
- Do not include text before or after the JSON.
- Analyze every email in the input list.
- The backend will calculate the final score and decide which emails to show.
- Your task is to provide category-level risk scores and explanations.

Evaluate each email according to:
1. Sender identity and possible impersonation
2. Subject line
3. Message body
4. Urgency or pressure tactics
5. Requests for passwords, login, payment, MFA codes, or personal data
6. Social engineering patterns
7. Suspicious links
8. Suspicious attachments
9. Overall phishing or malicious intent

Return ONLY valid JSON in this exact structure:

{{
  "emails": [
    {{
      "email_index": 0,
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
  ]
}}

Emails:
{json.dumps(email_items, ensure_ascii=False)}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    raw_text = response.output_text

    return parse_llm_json(raw_text)