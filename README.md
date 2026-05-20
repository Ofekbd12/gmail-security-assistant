# Gmail Security Assistant

## Project Summary
Gmail Security Assistant is a Gmail-integrated security add-on that helps users analyze suspicious emails directly inside Gmail.
The system allows users to scan the currently opened email or add selected emails to a controlled Scan Queue for batch analysis. Each analyzed email receives a clear risk score, verdict, explanation, recommended actions, and optional detailed breakdown by security risk category.
The backend uses an LLM to identify and explain suspicious email indicators, while the final risk score is calculated deterministically by the backend using a weighted scoring formula.

---

## Problem It Solves
Users often need to decide whether an email is trustworthy while they are already inside Gmail. Suspicious emails may include phishing attempts, fake login pages, social engineering messages, malicious links, or unsafe attachment indicators.
Gmail Security Assistant provides an on-demand security assistant inside Gmail.

---

## System Showcase

| Add-on Home Interface | Opened Email Interface |
| :---: | :---: |
| Initial Gmail Security Assistant interface inside Gmail. | Add-on interface when a specific email is opened. |
| <img src="screenshots/Security_Assistant_Home_Interface.png" width="380"> | <img src="screenshots/Security_Assistant_Mail_Page.png" width="380"> |

---

## Demo Videos

| Deep Single Email Scan | Batch Scan with Scan Queue | Malicious Email Detection |
| :---: | :---: | :---: |
| Full scan of one opened email, including detailed breakdown. | Selecting multiple emails and running batch analysis. | Detecting a deliberately suspicious demo email. |
| [Watch demo](screenshots/Security_Assistant_Mail_Scanning.mp4) | [Watch demo](screenshots/Security_Assistant_Batch_Scanning.mp4) | [Watch demo](screenshots/Security_Assistant_Malicious_Mail.mp4) |

---

## Key Features

- **Single Email Analysis:** Scan the currently opened Gmail message and receive a clear security assessment with risk score, verdict, summary, main reasons, and recommended actions.

- **Detailed Risk Breakdown:** View category-level explanations for Sender Risk, Content Risk, Social Engineering Risk, Link Risk, and Attachment Risk.

- **Deterministic Risk Scoring:** The LLM identifies risk signals, while the backend calculates the final score using a fixed weighted formula based on common phishing indicators.

- **Scan Queue:** Add selected emails to a controlled queue and scan multiple emails together.

- **Batch Email Analysis:** Analyze up to 7 selected emails in a single backend request, reducing latency and avoiding repeated LLM calls.

- **Focused Batch Report:** The batch scan returns only emails with a final score greater than 3/10, so the user sees only emails that require attention.

- **Full Scan from Batch Results:** After a batch scan, the user can run a deeper full analysis on a specific risky email from the queue results.

- **Dockerized Backend Deployment:** The FastAPI backend is containerized with Docker and deployed on Render using a Docker-based deployment flow.

- **Backend Tests:** The project includes pytest tests for deterministic scoring, verdict mapping, batch threshold logic, missing risk categories, negative scores, and score clamping.

---

## System Flowchart


---

The diagram below shows the main flow of the Gmail Security Assistant, including both the single-email analysis flow and the Scan Queue batch flow.

```mermaid
flowchart LR

    %% Gmail / User Entry
    subgraph GMAIL["📩 Gmail Interface"]
        A([User opens Gmail])
        B[Open Gmail Security Assistant Add-on]
        C{{Choose action}}
        A --> B --> C
    end

    %% Single Email Scan
    subgraph SINGLE["🔎 Single Email Scan"]
        D[Scan Current Email]
        E[Apps Script extracts current email data]
        F[Send request to FastAPI backend]
        G[LLM analyzes the email]
        H[Backend calculates deterministic final score]
        I[Return verdict, score, reasons, and actions]
        J[Display Email Risk Summary]
        K{{View detailed breakdown?}}
        L[Show Detailed Risk Breakdown]
        M([End])

        D --> E --> F --> G --> H --> I --> J --> K
        K -->|Yes| L --> M
        K -->|No| M
    end

    %% Scan Queue / Batch Flow
    subgraph QUEUE["📚 Scan Queue / Batch Flow"]
        N[Add Email to Scan Queue]
        O[Save selected email in queue]
        P[User may add up to 7 emails]
        Q[Scan Selected Emails]
        R[Send queued emails in one batch request]
        S[LLM analyzes selected emails in one batch call]
        T[Backend calculates deterministic scores]
        U[Return only emails with score greater than 3]
        V[Display focused batch report]
        W[Queue resets after successful scan]
        X([End])

        N --> O --> P --> Q --> R --> S --> T --> U --> V --> W --> X
    end

    %% Connections between flows
    C -->|Single email scan| D
    C -->|Add to scan queue| N
    V -. User may run full scan on one result .-> D

    %% Styles
    classDef gmail fill:#E3F2FD,stroke:#1E88E5,stroke-width:2px,color:#0D47A1;
    classDef scan fill:#E8F5E9,stroke:#43A047,stroke-width:2px,color:#1B5E20;
    classDef backend fill:#FFF3E0,stroke:#FB8C00,stroke-width:2px,color:#E65100;
    classDef decision fill:#F3E5F5,stroke:#8E24AA,stroke-width:2px,color:#4A148C;
    classDef endnode fill:#FFEBEE,stroke:#E53935,stroke-width:2px,color:#B71C1C;

    class A,B gmail;
    class C,K decision;
    class D,E,F,G,H,I,J,L,N,O,P,Q,R,S,T,U,V,W scan;
    class M,X endnode;
```
---

## Technical Stack

### Gmail Add-on

- **Google Apps Script** — used to build the Gmail add-on and connect it to Gmail.
- **Gmail Add-on CardService** — used to build the add-on UI, including cards, sections, buttons, summaries, and result screens.
- **Gmail Current Message Context** — used to access the email currently opened by the user.
- **PropertiesService** — used to store the Scan Queue state between Gmail screens.
- **CacheService** — used to temporarily store full scan results for the detailed breakdown screen.

### Backend

- **Python** — main backend language.
- **FastAPI** — used to expose the backend API endpoints.
- **Pydantic** — used for request and response validation.
- **OpenAI API** — used for LLM-based email risk analysis.
- **Uvicorn** — ASGI server used to run the FastAPI application.

### Deployment

- **Docker** — used to containerize the FastAPI backend.
- **Render** — used to deploy the Dockerized backend as a web service.
- **GitHub** — used for source code hosting and automatic deployment integration with Render.

### Testing

- **Pytest** — used to test the deterministic backend scoring logic and edge cases.

---

## Scoring Logic

The system uses the LLM to identify and explain suspicious email indicators, but the final score is calculated by the backend.

This separation makes the system more explainable and consistent:

```text
LLM
Identifies risk signals and explains them by category

Backend
Calculates the final score using deterministic logic

Final Score =
0.25 * Sender Risk
+ 0.20 * Content Risk
+ 0.20 * Social Engineering Risk
+ 0.25 * Link Risk
+ 0.10 * Attachment Risk

---

## Setup and Run

The recommended way to run the backend is with Docker.  
Running locally with Python is optional and mainly useful for development or debugging.

### Run with Docker

1. Clone the repository:

```bash
git clone <your-repository-url>
cd gmail-security-assistant
```

2. Create a `.env` file in the project root:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

3. Build and run the backend container:

```bash
docker build -t gmail-security-assistant-backend .
docker run --env-file .env -p 8000:10000 gmail-security-assistant-backend
```

4. Verify the backend is running:

```text
http://localhost:8000/
```

Optional API documentation:

```text
http://localhost:8000/docs
```

---

### Optional: Run Locally without Docker

```bash
python -m pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000/
```

---

### Gmail Add-on Setup

1. Open Google Apps Script.
2. Copy the code from `gmail-addon/Code.gs`.
3. Copy the manifest from `gmail-addon/appsscript.json`.
4. Save the Apps Script project.
5. Install the test deployment.
6. Open Gmail and launch the Gmail Security Assistant add-on.

---

## Testing

The backend includes unit tests for the deterministic scoring logic and important edge cases.

The tests cover:

- Weighted final score calculation
- Verdict mapping
- Safe, Suspicious, and Malicious analysis flows
- Batch scan inclusion threshold
- Missing risk category handling
- Negative score handling
- Score clamping above 10

Run tests with:

```bash
python -m pytest