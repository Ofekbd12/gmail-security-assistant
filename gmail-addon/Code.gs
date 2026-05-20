const BACKEND_ANALYZE_URL =
  "https://gmail-security-assistant.onrender.com/analyze-email";

const BACKEND_INITIAL_SCAN_URL =
  "https://gmail-security-assistant.onrender.com/initial-inbox-scan";

const MAX_INITIAL_EMAILS = 20;
const INITIAL_SCAN_QUERY = "in:inbox is:unread newer_than:2d";

function onGmailMessageOpen(e) {
  return buildInitialInboxScanCard(e);
}

function buildHomeCard(e) {
  return buildInitialInboxScanCard(e);
}

function buildInitialInboxScanCard(e) {
  try {
    const recentEmails = getRecentInboxEmails();

    if (recentEmails.length === 0) {
      return buildSafeInboxCard(
        0,
        "No recent unread inbox emails were found.",
        e
      );
    }

    const scanResult = callInitialInboxScanBackend(recentEmails);

    if (!scanResult.suspicious_emails_found) {
      return buildSafeInboxCard(
        scanResult.total_emails_scanned,
        "No suspicious emails were detected in recent unread inbox messages.",
        e
      );
    }

    return buildInitialScanReportCard(scanResult, recentEmails, e);

  } catch (error) {
    return buildErrorCard(error);
  }
}

function getRecentInboxEmails() {
  const threads = GmailApp.search(
    INITIAL_SCAN_QUERY,
    0,
    MAX_INITIAL_EMAILS
  );

  const emails = [];

  threads.forEach(function (thread) {
    const messages = thread.getMessages();
    const message = messages[messages.length - 1];

    const body = message.getPlainBody();
    const attachments = message.getAttachments().map(function (attachment) {
      return attachment.getName();
    });

    emails.push({
      messageId: message.getId(),
      sender: message.getFrom(),
      subject: message.getSubject(),
      body: body.substring(0, 4000),
      links: extractLinks(body),
      attachments: attachments
    });
  });

  return emails;
}

function callInitialInboxScanBackend(emails) {
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

  const response = UrlFetchApp.fetch(BACKEND_INITIAL_SCAN_URL, options);
  const statusCode = response.getResponseCode();
  const responseText = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error(
      "Initial inbox scan failed with status " +
      statusCode +
      ": " +
      responseText
    );
  }

  return JSON.parse(responseText);
}

function buildSafeInboxCard(totalScanned, message, e) {
  const header = CardService.newCardHeader()
    .setTitle("✅ INBOX LOOKS SAFE")
    .setSubtitle("Initial inbox safety check completed");

  const section = CardService.newCardSection()
    .setHeader("Inbox Safety Report")
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Emails scanned:</b><br>" + totalScanned
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Status:</b><br>" + escapeHtml(message)
      )
    );

  addManualScanButtonIfPossible(section, e);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(section)
    .build();
}

function buildInitialScanReportCard(scanResult, recentEmails, e) {
  const header = CardService.newCardHeader()
    .setTitle("🚨 SUSPICIOUS EMAILS FOUND")
    .setSubtitle(
      scanResult.suspicious_emails_count +
      " risky email(s) detected"
    );

  const summarySection = CardService.newCardSection()
    .setHeader("Initial Inbox Scan")
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Total emails scanned:</b><br>" +
        scanResult.total_emails_scanned
      )
    )
    .addWidget(CardService.newTextParagraph().setText("<br>"))
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>Suspicious emails found:</b><br>" +
        scanResult.suspicious_emails_count
      )
    );

  const suspiciousSection = CardService.newCardSection()
    .setHeader("Security Report");

  scanResult.suspicious_emails.forEach(function (emailSummary, index) {
    const matchedEmail = findMatchingEmail(recentEmails, emailSummary);

    suspiciousSection.addWidget(
      CardService.newTextParagraph().setText(
        "<b>" +
        (index + 1) +
        ". " +
        escapeHtml(emailSummary.display_label).toUpperCase() +
        "</b><br><br>" +
        "<b>From:</b><br>" +
        escapeHtml(emailSummary.sender) +
        "<br><br>" +
        "<b>Subject:</b><br>" +
        escapeHtml(emailSummary.subject) +
        "<br><br>" +
        "<b>Risk Score:</b><br>" +
        emailSummary.score +
        "/10" +
        "<br><br>" +
        "<b>Verdict:</b><br>" +
        escapeHtml(emailSummary.verdict) +
        "<br><br>" +
        "<b>Summary:</b><br>" +
        escapeHtml(emailSummary.summary)
      )
    );

    if (matchedEmail) {
      suspiciousSection.addWidget(
        CardService.newTextButton()
          .setText("View Details")
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName("onViewInitialEmailDetails")
              .setParameters({
                messageId: matchedEmail.messageId
              })
          )
      );
    }

    suspiciousSection.addWidget(
      CardService.newTextParagraph().setText("<br>")
    );
  });

  addManualScanButtonIfPossible(suspiciousSection, e);

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(summarySection)
    .addSection(suspiciousSection)
    .build();
}

function findMatchingEmail(recentEmails, emailSummary) {
  for (let i = 0; i < recentEmails.length; i++) {
    const email = recentEmails[i];

    if (
      email.sender === emailSummary.sender &&
      email.subject === emailSummary.subject
    ) {
      return email;
    }
  }

  return null;
}

function addManualScanButtonIfPossible(section, e) {
  if (!e || !e.gmail || !e.gmail.messageId) {
    return;
  }

  section.addWidget(CardService.newTextParagraph().setText("<br>"));

  section.addWidget(
    CardService.newTextButton()
      .setText("Scan Current Email")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(
        CardService.newAction().setFunctionName("onScanEmail")
      )
  );
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

function onViewInitialEmailDetails(e) {
  try {
    const messageId = e.parameters.messageId;
    const emailData = getEmailDataByMessageId(messageId);
    const analysis = callAnalyzeEmailBackend(emailData);

    saveAnalysisToCache(messageId, analysis);

    const detailsCard = buildAnalysisSummaryCard(emailData, analysis);

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

function getCurrentEmailData(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  return getEmailDataByMessageId(e.gmail.messageId);
}

function getEmailDataByMessageId(messageId) {
  const message = GmailApp.getMessageById(messageId);

  const sender = message.getFrom();
  const subject = message.getSubject();
  const body = message.getPlainBody();

  const attachments = message.getAttachments().map(function (attachment) {
    return attachment.getName();
  });

  const links = extractLinks(body);

  return {
    messageId: messageId,
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