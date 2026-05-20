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
  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Scan")
        .setSubtitle("Backend connection will be added next")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            "The Scan Email button is working. Next step: connect this action to the FastAPI backend."
          )
        )
    )
    .build();

  return card;
}