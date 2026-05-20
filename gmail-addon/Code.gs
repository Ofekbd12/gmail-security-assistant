const BACKEND_ANALYZE_URL =
  "https://gmail-security-assistant.onrender.com/analyze-email";

function onGmailMessageOpen(e) {
  return buildHomeCard();
}

function buildHomeCard() {
  const header = CardService.newCardHeader()
    .setTitle("Gmail Security Assistant")
    .setSubtitle("Analyze emails for phishing and malicious signals");

  const scanButton = CardService.newTextButton()
    .setText("Scan Email")
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(
      CardService.newAction().setFunctionName("onScanEmail")
    );

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Open an email and click Scan Email to analyze its risk level."
      )
    )
    .addWidget(scanButton);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function onScanEmail(e) {
  try {
    const emailData = getCurrentEmailData(e);
    const analysis = callAnalyzeEmailBackend(emailData);

    saveAnalysisToCache(emailData.messageId, analysis);

    const resultCard = buildAnalysisSummaryCard(emailData, analysis);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(resultCard)
      )
      .build();

  } catch (error) {
    const errorCard = buildErrorCard(error);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(errorCard)
      )
      .build();
  }
}

function getCurrentEmailData(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  const message = GmailApp.getMessageById(e.gmail.messageId);

  const sender = message.getFrom();
  const subject = message.getSubject();
  const body = message.getPlainBody();

  const attachments = message.getAttachments().map(function (attachment) {
    return attachment.getName();
  });

  const links = extractLinks(body);

  return {
    messageId: e.gmail.messageId,
    sender: sender,
    subject: subject,
    body: body.substring(0, 4000),
    links: links,
    attachments: attachments
  };
}

function extractLinks(text) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const matches = text.match(urlRegex);

  if (!matches) {
    return [];
  }

  return matches;
}

function callAnalyzeEmailBackend(emailData) {
  const payload = {
    sender: emailData.sender,
    subject: emailData.subject,
    body: emailData.body,
    links: emailData.links,
    attachments: emailData.attachments
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  const response = UrlFetchApp.fetch(BACKEND_ANALYZE_URL, options);
  const statusCode = response.getResponseCode();
  const responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(
      "Backend request failed with status " +
      statusCode +
      ": " +
      responseText
    );
  }

  return JSON.parse(responseText);
}

function buildAnalysisSummaryCard(emailData, analysis) {
  const severityEmoji = getSeverityEmoji(analysis.severity_color);
  const displayLabel = String(analysis.display_label).toUpperCase();

  const header = CardService.newCardHeader()
    .setTitle(severityEmoji + " " + displayLabel)
    .setSubtitle("Risk Score: " + analysis.score + "/10");

  const summarySection = CardService.newCardSection()
    .setHeader("Email Risk Summary")
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>From:</b><br>" + escapeHtml(emailData.sender)
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText("<br>")
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Subject:</b><br>" + escapeHtml(emailData.subject)
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText("<br>")
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Verdict:</b><br><b>" +
        severityEmoji +
        " " +
        displayLabel +
        "</b>"
      )
    )
    .addWidget(
      CardService.newTextParagraph().setText("<br>")
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Summary:</b><br>" + escapeHtml(analysis.summary)
      )
    );

  const reasonsSection = CardService.newCardSection()
    .setHeader("Main Reasons");

  analysis.reasons.forEach(function (reason) {
    reasonsSection.addWidget(
      CardService.newTextParagraph().setText(
        "• " + escapeHtml(reason)
      )
    );

    reasonsSection.addWidget(
      CardService.newTextParagraph().setText("<br>")
    );
  });

  const actionsSection = CardService.newCardSection()
    .setHeader("Recommended Actions");

  analysis.recommended_actions.forEach(function (action) {
    actionsSection.addWidget(
      CardService.newTextParagraph().setText(
        "• " + escapeHtml(action)
      )
    );

    actionsSection.addWidget(
      CardService.newTextParagraph().setText("<br>")
    );
  });

  const detailsButton = CardService.newTextButton()
    .setText("View Details")
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(
      CardService.newAction()
        .setFunctionName("onViewDetails")
        .setParameters({
          messageId: emailData.messageId
        })
    );

  const footerSection = CardService.newCardSection()
    .addWidget(detailsButton);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(summarySection)
    .addSection(reasonsSection)
    .addSection(actionsSection)
    .addSection(footerSection)
    .build();
}

function onViewDetails(e) {
  try {
    const messageId = e.parameters.messageId;
    const analysis = getAnalysisFromCache(messageId);

    if (!analysis) {
      throw new Error("Analysis details expired. Please scan the email again.");
    }

    const detailsCard = buildDetailsCard(analysis);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(detailsCard)
      )
      .build();

  } catch (error) {
    const errorCard = buildErrorCard(error);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(errorCard)
      )
      .build();
  }
}

function buildDetailsCard(analysis) {
  const header = CardService.newCardHeader()
    .setTitle("Detailed Risk Breakdown")
    .setSubtitle("Risk score per security criterion");

  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        buildRiskBreakdownText(analysis.risk_breakdown)
      )
    );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function buildRiskBreakdownText(riskBreakdown) {
  const lines = [];

  lines.push(formatRiskCategory("Sender Risk", riskBreakdown.sender_risk));
  lines.push(formatRiskCategory("Content Risk", riskBreakdown.content_risk));
  lines.push(
    formatRiskCategory(
      "Social Engineering Risk",
      riskBreakdown.social_engineering_risk
    )
  );
  lines.push(formatRiskCategory("Link Risk", riskBreakdown.link_risk));
  lines.push(
    formatRiskCategory("Attachment Risk", riskBreakdown.attachment_risk)
  );

  return lines.join("<br><br>");
}

function formatRiskCategory(label, category) {
  return (
    "<b>" +
    escapeHtml(label) +
    ":</b> " +
    category.score +
    "/" +
    category.max_score +
    "<br>" +
    escapeHtml(category.explanation)
  );
}

function saveAnalysisToCache(messageId, analysis) {
  const cache = CacheService.getUserCache();
  const key = "analysis_" + messageId;

  cache.put(key, JSON.stringify(analysis), 600);
}

function getAnalysisFromCache(messageId) {
  const cache = CacheService.getUserCache();
  const key = "analysis_" + messageId;
  const cachedValue = cache.get(key);

  if (!cachedValue) {
    return null;
  }

  return JSON.parse(cachedValue);
}

function buildErrorCard(error) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Scan Failed")
        .setSubtitle("Could not analyze this email")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            "Something went wrong while scanning the email."
          )
        )
        .addWidget(
          CardService.newTextParagraph().setText(
            "<b>Error:</b> " + escapeHtml(error.message)
          )
        )
    )
    .build();
}

function getSeverityEmoji(severityColor) {
  if (severityColor === "red") {
    return "🚨";
  }

  if (severityColor === "orange") {
    return "⚠️";
  }

  if (severityColor === "yellow") {
    return "🟡";
  }

  return "✅";
}

function escapeHtml(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}