const BACKEND_ANALYZE_URL =
  "https://gmail-security-assistant.onrender.com/analyze-email";

const BACKEND_BATCH_ANALYZE_URL =
  "https://gmail-security-assistant.onrender.com/analyze-email-batch";

const MAX_QUEUE_EMAILS = 7;
const QUEUE_IDS_KEY = "scan_queue_ids";

function onGmailMessageOpen(e) {
  return buildHomeCard(e);
}

function buildHomeCard(e) {
  const queueIds = getScanQueueIds();
  const queueCount = queueIds.length;
  const remainingSlots = MAX_QUEUE_EMAILS - queueCount;

  const header = CardService.newCardHeader()
    .setTitle("Gmail Security Assistant")
    .setSubtitle("Analyze selected emails for phishing and malicious signals");

  const section = CardService.newCardSection();

  addSectionTitle(section, "🛡️ Email Security Scan");

  section
    .addWidget(
      CardService.newTextParagraph().setText(
        "Scan the opened email, or add it to a controlled scan queue."
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Scan Queue:</b><br>" +
        queueCount +
        "/" +
        MAX_QUEUE_EMAILS +
        " emails selected"
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Remaining slots:</b><br>" + remainingSlots
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"));

  if (e && e.gmail && e.gmail.messageId) {
    section.addWidget(
      CardService.newTextButton()
        .setText("Scan Current Email")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(
          CardService.newAction().setFunctionName("onScanEmail")
        )
    );

    section.addWidget(CardService.newTextParagraph().setText("<br>"));

    section.addWidget(
      CardService.newTextButton()
        .setText("Add Email to Scan Queue")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(
          CardService.newAction().setFunctionName("onAddToScanQueue")
        )
    );

    section.addWidget(CardService.newTextParagraph().setText("<br>"));
  }

  if (queueCount > 0) {
    section.addWidget(
      CardService.newTextButton()
        .setText("Scan Selected Emails")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(
          CardService.newAction().setFunctionName("onScanQueue")
        )
    );

    section.addWidget(CardService.newTextParagraph().setText("<br>"));

    section.addWidget(
      CardService.newTextButton()
        .setText("Clear Queue")
        .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
        .setOnClickAction(
          CardService.newAction().setFunctionName("onClearQueue")
        )
    );
  }

  if ((!e || !e.gmail || !e.gmail.messageId) && queueCount === 0) {
    section.addWidget(
      CardService.newTextParagraph().setText(
        "Open an email message to scan it or add it to the scan queue."
      )
    );
  }

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

function onAddToScanQueue(e) {
  try {
    const emailData = getCurrentEmailData(e);
    const queueIds = getScanQueueIds();

    if (queueIds.indexOf(emailData.messageId) !== -1) {
      return buildActionResponseCard(
        "Already in Queue",
        "This email is already included in the scan queue.",
        e
      );
    }

    if (queueIds.length >= MAX_QUEUE_EMAILS) {
      return buildActionResponseCard(
        "Scan Queue Full",
        "You already selected " +
          MAX_QUEUE_EMAILS +
          " emails. Scan or clear the queue before adding more.",
        e
      );
    }

    saveQueuedEmail(emailData);

    queueIds.push(emailData.messageId);
    saveScanQueueIds(queueIds);

    return buildActionResponseCard(
      "Email Added",
      "This email was added to the scan queue. Queue status: " +
        queueIds.length +
        "/" +
        MAX_QUEUE_EMAILS +
        ".",
      e
    );

  } catch (error) {
    const errorCard = buildErrorCard(error);

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(errorCard)
      )
      .build();
  }
}

function onScanQueue(e) {
  try {
    const queuedEmails = getQueuedEmails();

    if (queuedEmails.length === 0) {
      return buildActionResponseCard(
        "Scan Queue Empty",
        "No emails were selected for batch scanning.",
        e
      );
    }

    const batchResult = callBatchAnalyzeEmailBackend(queuedEmails);

    const resultsCard = buildQueueResultsCard(
      batchResult,
      queuedEmails
    );

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(resultsCard)
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

function onClearQueue(e) {
  clearScanQueue();

  return buildActionResponseCard(
    "Queue Cleared",
    "The scan queue was cleared successfully.",
    e
  );
}

function buildActionResponseCard(title, message, e) {
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        escapeHtml(message)
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"));

  section.addWidget(
    CardService.newTextButton()
      .setText("Back to Scan Menu")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(
        CardService.newAction().setFunctionName("onBackToHome")
      )
  );

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle(title)
        .setSubtitle("Gmail Security Assistant")
    )
    .addSection(section)
    .build();

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(card)
    )
    .build();
}

function onBackToHome(e) {
  const card = buildHomeCard(e);

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(card)
    )
    .build();
}

function buildQueueResultsCard(batchResult, queuedEmails) {
  const header = CardService.newCardHeader()
    .setTitle("Scan Queue Results")
    .setSubtitle(batchResult.emails_analyzed + " selected email(s) analyzed");

  const section = CardService.newCardSection();

  addSectionTitle(section, "📋 Selected Emails Report");

  if (!batchResult.risky_emails_found) {
    section
      .addWidget(
        CardService.newTextParagraph().setText(
          "No emails with score 5/10 or higher were found in the selected queue."
        )
      )
      .addWidget(CardService.newTextParagraph().setText("<br>"))
      .addWidget(
        CardService.newTextParagraph().setText(
          "Only emails that require user attention are shown in this report."
        )
      );

    return CardService.newCardBuilder()
      .setHeader(header)
      .addSection(section)
      .build();
  }

  batchResult.risky_emails.forEach(function (result, index) {
    const emailData = queuedEmails[result.email_index];
    const severityEmoji = getSeverityEmoji(result.severity_color);
    const displayLabel = String(result.display_label).toUpperCase();

    saveAnalysisToCache(emailData.messageId, result);

    section.addWidget(
      CardService.newTextParagraph().setText(
        "<b>" +
        (index + 1) +
        ". " +
        severityEmoji +
        " " +
        displayLabel +
        "</b><br><br>" +
        "<b>From:</b><br>" +
        escapeHtml(result.sender) +
        "<br><br>" +
        "<b>Subject:</b><br>" +
        escapeHtml(result.subject) +
        "<br><br>" +
        "<b>Risk Score:</b><br>" +
        result.score +
        "/10" +
        "<br><br>" +
        "<b>Summary:</b><br>" +
        escapeHtml(result.summary)
      )
    );

    section.addWidget(
      CardService.newTextButton()
        .setText("Run Full Detailed Scan")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("onRunFullScanFromQueue")
            .setParameters({
              messageId: emailData.messageId
            })
        )
    );

    section.addWidget(CardService.newTextParagraph().setText("<br>"));
  });

  section.addWidget(
    CardService.newTextButton()
      .setText("Clear Queue")
      .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
      .setOnClickAction(
        CardService.newAction().setFunctionName("onClearQueue")
      )
  );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function onRunFullScanFromQueue(e) {
  try {
    const messageId = e.parameters.messageId;
    const emailData = getQueuedEmailById(messageId);

    if (!emailData) {
      throw new Error("Queued email not found. Please add it again.");
    }

    const analysis = callAnalyzeEmailBackend(emailData);
    saveAnalysisToCache(messageId, analysis);

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
    body: body.substring(0, 3000),
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

function callBatchAnalyzeEmailBackend(emails) {
  const payload = {
    emails: emails.map(function (email) {
      return {
        sender: email.sender,
        subject: email.subject,
        body: email.body,
        links: email.links,
        attachments: email.attachments
      };
    })
  };

  const options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  const response = UrlFetchApp.fetch(BACKEND_BATCH_ANALYZE_URL, options);
  const statusCode = response.getResponseCode();
  const responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(
      "Batch backend request failed with status " +
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

  const summarySection = CardService.newCardSection();

  addSectionTitle(summarySection, "📌 Email Risk Summary");

  summarySection
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>From:</b><br>" + escapeHtml(emailData.sender)
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Subject:</b><br>" + escapeHtml(emailData.subject)
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Verdict:</b><br><b>" +
        severityEmoji +
        " " +
        displayLabel +
        "</b>"
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Summary:</b><br>" + escapeHtml(analysis.summary)
      )
    );

  const reasonsSection = CardService.newCardSection();

  addSectionTitle(reasonsSection, "🔎 Main Reasons");

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

  const actionsSection = CardService.newCardSection();

  addSectionTitle(actionsSection, "✅ Recommended Actions");

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
    .setText("View Detailed Breakdown")
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

    if (!analysis || !analysis.risk_breakdown) {
      throw new Error(
        "Detailed breakdown is available only after running a full detailed scan."
      );
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

  const section = CardService.newCardSection();

  addSectionTitle(section, "🧩 Detailed Risk Breakdown");

  section.addWidget(
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

function addSectionTitle(section, title) {
  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>" + escapeHtml(title) + "</b>"
    )
  );

  section.addWidget(
    CardService.newTextParagraph().setText("<br>")
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

function getScanQueueIds() {
  const properties = PropertiesService.getUserProperties();
  const rawValue = properties.getProperty(QUEUE_IDS_KEY);

  if (!rawValue) {
    return [];
  }

  return JSON.parse(rawValue);
}

function saveScanQueueIds(queueIds) {
  const properties = PropertiesService.getUserProperties();
  properties.setProperty(QUEUE_IDS_KEY, JSON.stringify(queueIds));
}

function saveQueuedEmail(emailData) {
  const properties = PropertiesService.getUserProperties();
  const key = getQueueItemKey(emailData.messageId);

  properties.setProperty(key, JSON.stringify(emailData));
}

function getQueuedEmails() {
  const properties = PropertiesService.getUserProperties();
  const queueIds = getScanQueueIds();

  const emails = [];

  queueIds.forEach(function (messageId) {
    const rawValue = properties.getProperty(getQueueItemKey(messageId));

    if (rawValue) {
      emails.push(JSON.parse(rawValue));
    }
  });

  return emails;
}

function getQueuedEmailById(messageId) {
  const properties = PropertiesService.getUserProperties();
  const rawValue = properties.getProperty(getQueueItemKey(messageId));

  if (!rawValue) {
    return null;
  }

  return JSON.parse(rawValue);
}

function clearScanQueue() {
  const properties = PropertiesService.getUserProperties();
  const queueIds = getScanQueueIds();

  queueIds.forEach(function (messageId) {
    properties.deleteProperty(getQueueItemKey(messageId));
  });

  properties.deleteProperty(QUEUE_IDS_KEY);
}

function getQueueItemKey(messageId) {
  return "scan_queue_item_" + messageId;
}

function buildErrorCard(error) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Scan Failed")
        .setSubtitle("Could not complete the requested scan")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            "Something went wrong while scanning."
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