function buildAddOn(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  var fromStr = message.getFrom();
  var senderEmail = fromStr;
  var senderName = fromStr;
  var emailMatch = fromStr.match(/<(.*)>/);
  if (emailMatch) {
    senderEmail = emailMatch[1];
    senderName = fromStr.replace(/<.*>/, '').trim();
  }

  var htmlBody = message.getBody();
  var links = [];
  var regex = /href="(https?:\/\/[^"]+)"/g;
  var match;
  while (match = regex.exec(htmlBody)) {
    links.push(match[1]);
  }

  var attachments = message.getAttachments().map(function(a) { return a.getName(); });

  var payload = {
    "target_email": Session.getActiveUser().getEmail(), // זיהוי העובד המותקף לטובת הדשבורד
    "sender_email": senderEmail,
    "sender_name": senderName,
    "subject": message.getSubject(),
    "body": message.getPlainBody(),
    "links": links,
    "attachments": attachments,
    "is_first_time_sender": true
  };

  var options = {
    'method' : 'post',
    'contentType': 'application/json',
    'headers': {
      'X-Upwind-Auth': 'upwind-sec-token-2026',
      'ngrok-skip-browser-warning': 'true'
    },
    'payload' : JSON.stringify(payload),
    'muteHttpExceptions': true
  };

  try {
    var response = UrlFetchApp.fetch('https://goldfish-fresh-usable.ngrok-free.dev/analyze', options);
    var result = JSON.parse(response.getContentText());
    
    return createCard(result);
  } catch (err) {
    return createErrorCard(err.toString());
  }
}

function createCard(result) {
  var card = CardService.newCardBuilder();
  
  // קביעת צבע ויזואלי (תצוגת רמזור)
  var color = "#4CAF50"; // ירוק כברירת מחדל
  if (result.score >= 60) {
    color = "#F44336"; // אדום
  } else if (result.score >= 30) {
    color = "#FF9800"; // צהוב
  }

  var section = CardService.newCardSection();
  
  // הוספת פסק דין עם צבע
  var verdictHtml = "<b>Verdict:</b> <font color='" + color + "'>" + result.verdict + "</font>";
  section.addWidget(CardService.newTextParagraph().setText(verdictHtml));
  section.addWidget(CardService.newTextParagraph().setText("<b>Risk Score:</b> " + result.score + "/100"));

  // הצגת סיבות 
  if (result.reasons && result.reasons.length > 0) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Analysis & Context:</b>"));
    result.reasons.forEach(function(r) {
      section.addWidget(CardService.newTextParagraph().setText("• " + r));
    });
  }

  // --- יצירת כפתורי פעולה אקטיביים ---
  var actionSet = CardService.newButtonSet();
  
  // כפתור דיווח
  var reportAction = CardService.newAction().setFunctionName("notifyAction").setParameters({"msg": "Email reported to SecOps successfully."});
  actionSet.addButton(CardService.newTextButton().setText("Report to SecOps").setBackgroundColor("#F44336").setOnClickAction(reportAction));
  
  // כפתור אישור
  var safeAction = CardService.newAction().setFunctionName("notifyAction").setParameters({"msg": "Sender marked as safe."});
  actionSet.addButton(CardService.newTextButton().setText("Mark as Safe").setOnClickAction(safeAction));

  section.addWidget(actionSet);

  // --- שילוב פלייבוק ו-AI ---
  var toolsSet = CardService.newButtonSet();
  
  // כפתור Playbook שפותח קישור (הדגמה לחשיבה אופרטיבית)
  toolsSet.addButton(CardService.newTextButton().setText("Security Playbook")
    .setOpenLink(CardService.newOpenLink().setUrl("https://www.upwind.com/security")));
  
  // כפתור התייעצות עם AI מדומה
  var aiAction = CardService.newAction().setFunctionName("notifyAction").setParameters({"msg": "Feature 'Internal Security AI Copilot' is currently in roadmap. Stay tuned!"});
  toolsSet.addButton(CardService.newTextButton().setText("Ask Internal AI").setOnClickAction(aiAction));

  section.addWidget(toolsSet);

  card.addSection(section);
  return card.build();
}

function notifyAction(e) {
  // הפעלת הודעה צפה קטנה (Toast) בממשק ג'ימייל
  var message = e.parameters.msg;
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(message))
    .build();
}

function createErrorCard(error) {
   var card = CardService.newCardBuilder();
   var section = CardService.newCardSection();
   section.addWidget(CardService.newTextParagraph().setText("Error: " + error));
   card.addSection(section);
   return card.build();
}