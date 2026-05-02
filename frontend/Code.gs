const BACKEND_URL = 'https://crying-brunt-upturned.ngrok-free.dev/api/scan';

function buildAddOn(e) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Upwind Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText('Welcome to the Upwind Malicious Email Scorer.\n\nClick below to scan this email and analyze its threat level.'))
        .addWidget(
          CardService.newTextButton()
            .setText('Scan Email')
            .setOnClickAction(CardService.newAction().setFunctionName('scanEmail'))
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        )
    )
    .build();

  return card;
}

function scanEmail(e) {
  try {
    const messageId = e.gmail.messageId;
    const message = GmailApp.getMessageById(messageId);
    
    // Extract Body
    const body = message.getPlainBody() || message.getBody();
    
    // Extract Headers from raw content
    const rawContent = message.getRawContent();
    const rawHeaders = rawContent.split('\r\n\r\n')[0];
    const headersArray = rawHeaders.split('\r\n');
    
    const headersMap = {};
    const receivedChain = [];
    var currentHeader = '';
    
    // Parse headers manually to handle multi-line headers
    for (var i = 0; i < headersArray.length; i++) {
      var line = headersArray[i];
      if (line.match(/^\s+/)) {
        currentHeader += ' ' + line.trim();
      } else {
        if (currentHeader) {
          processHeader(currentHeader, headersMap, receivedChain);
        }
        currentHeader = line;
      }
    }
    if (currentHeader) {
      processHeader(currentHeader, headersMap, receivedChain);
    }
    
    const headersObj = {
      from: headersMap['from'] || message.getFrom(),
      replyTo: headersMap['reply-to'] || message.getReplyTo() || message.getFrom(),
      subject: headersMap['subject'] || message.getSubject(),
      receivedSpf: headersMap['received-spf'] || '',
      dkimSignature: headersMap['dkim-signature'] || '',
      authenticationResults: headersMap['authentication-results'] || '',
      receivedChain: receivedChain
    };
    
    // Extract Attachments
    const attachments = message.getAttachments().map(function(att) {
      return {
        filename: att.getName(),
        mimeType: att.getContentType(),
        size: att.getSize(),
        contentBase64: Utilities.base64Encode(att.getBytes())
      };
    });
    
    const payload = {
      body: body,
      headers: headersObj,
      attachments: attachments
    };
    
    // Auth Token
    const token = ScriptApp.getIdentityToken();
    const apiKey = PropertiesService.getScriptProperties().getProperty('UPWIND_API_KEY');
    
    // Networking
    const options = {
      method: 'post',
      contentType: 'application/json',
      headers: {
        'Authorization': 'Bearer ' + token,
        'x-api-key': apiKey || ''
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };
    
    const response = UrlFetchApp.fetch(BACKEND_URL, options);
    const responseCode = response.getResponseCode();
    
    if (responseCode !== 200) {
      throw new Error('Backend returned status ' + responseCode + ':\n' + response.getContentText());
    }
    
    const result = JSON.parse(response.getContentText());
    
    // Return action response to push the new card
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildResultCard(result)))
      .build();
    
  } catch (error) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildErrorCard(error.message || 'An unknown error occurred.')))
      .build();
  }
}

function processHeader(headerLine, map, receivedChain) {
  const match = headerLine.match(/^([^:]+):\s*(.*)$/i);
  if (match) {
    const key = match[1].toLowerCase();
    const val = match[2];
    if (key === 'received') {
      receivedChain.push(val);
    } else if (!map[key]) {
      // Only keep the first occurrence of standard headers
      map[key] = val; 
    }
  }
}

function buildResultCard(result) {
  var verdictColorEmoji = '✅';
  var colorString = '#0F9D58'; // Green
  
  const score = result.score || 0;
  
  if (score >= 85) {
    verdictColorEmoji = '🔴';
    colorString = '#DB4437'; // Red
  } else if (score >= 60) {
    verdictColorEmoji = '🔶';
    colorString = '#F4B400'; // Orange
  } else if (score >= 30) {
    verdictColorEmoji = '⚠️';
    colorString = '#F4B400'; // Yellow/Amber
  }
  
  const verdictText = verdictColorEmoji + ' ' + (result.verdict || 'Unknown');
  
  const section = CardService.newCardSection()
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel('Composite Risk Score')
        .setContent('<font color="' + colorString + '"><b>' + score + ' / 100</b></font>')
    )
    .addWidget(
      CardService.newKeyValue()
        .setTopLabel('Verdict')
        .setContent('<b>' + verdictText + '</b>')
    );
    
  if (result.signals && Array.isArray(result.signals)) {
    result.signals.forEach(function(sig) {
      section.addWidget(CardService.newDivider());
      section.addWidget(
        CardService.newKeyValue()
          .setTopLabel(sig.name || 'Signal')
          .setContent('Score: ' + (sig.score || 0))
          .setBottomLabel(sig.details || 'No details provided.')
          .setMultiline(true)
      );
    });
  }

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Scan Results'))
    .addSection(section)
    .build();
}

function buildErrorCard(errorMsg) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Error Scanning Email'))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText('An error occurred while scanning the email:\n\n<font color="#DB4437">' + errorMsg + '</font>')
        )
        .addWidget(
          CardService.newTextButton()
            .setText('Dismiss')
            .setOnClickAction(CardService.newAction().setFunctionName('dismissError'))
        )
    )
    .build();
}

// Helper to pop the error card
function dismissError(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}
