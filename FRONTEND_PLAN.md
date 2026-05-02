# Frontend Architecture Plan: Gmail Add-on

## 1. Directory Structure

All frontend code for the Gmail Add-on will be isolated from the Node.js backend to ensure a clear separation of concerns. They will reside in a dedicated directory in the project root:

```text
frontend/
├── appsscript.json   # The Add-on manifest (configuration & permissions)
└── Code.gs           # The core Apps Script logic (UI generation & networking)
```

## 2. Manifest (`appsscript.json`)

The manifest defines how the Add-on integrates with Google Workspace. It will be configured strictly as a **Gmail Add-on**.

**Key Requirements:**
- **Scopes:** The Add-on requires minimal privileges to operate:
  - `https://www.googleapis.com/auth/gmail.addons.execute` (Required to run the Add-on UI)
  - `https://www.googleapis.com/auth/gmail.readonly` (Required to extract email body, headers, and attachments)
- **Contextual Trigger:** A contextual trigger will be defined to fire unconditionally whenever the user opens an email. This trigger will execute the main UI entry point function (e.g., `buildAddOn(e)`), passing the active email context to the script.

## 3. UI Engine (`Code.gs` - UI Generation)

The Add-on's interface will be constructed entirely using Google Apps Script's **Card Service** (`CardService`). The Add-on will primarily transition between two states:

### 3.1. Welcome Card
This is the default view presented when an email is opened.
- **Content:** A simple, clean greeting.
- **Action:** A prominent "Scan Email" button. Clicking this button triggers the data extraction and networking flow.

### 3.2. Result Card
This view is rendered dynamically after receiving a successful response from the Node.js backend. It displays the scan results:
- **Score:** The composite risk score (0–100) returned by the backend.
- **Verdict:** A human-readable label, visually color-coded to immediately convey risk:
  - 🔴 **Red** (85–100): Critical Risk
  - 🔶 **Orange** (60–84): High Risk
  - ⚠️ **Yellow** (30–59): Medium Risk
  - ✅ **Green** (0–29): Low Risk
- **Signal Breakdown:** A detailed list/section enumerating each signal (e.g., Metadata & Spoofing, Sender Reputation, Attachment Analysis), including their individual scores and specific explanations as provided by the backend.

### 3.3. Error Card / Notification
The UI must be able to gracefully handle and display errors. If an issue occurs (e.g., "Backend unreachable", "Timeout"), an Error Card will be rendered to inform the user, preventing the Add-on from crashing or freezing.

## 4. Data Extraction & Networking (`Code.gs` - Logic)

The logic layer acts as the bridge between the Gmail user interface and the secure Node.js backend.

### 4.1. Data Extraction
When the "Scan Email" button is clicked, the action function will extract data from the active email:
1. **Context:** Receive the `event` object (`e`) passed by the Card action.
2. **Message Identification:** Extract the active message's ID using `e.gmail.messageId`.
3. **Retrieval:** Use `GmailApp.getMessageById(messageId)` to retrieve the full message instance.
4. **Payload Construction (Aligning with `DESIGN.md`):**
   - **Body:** Extract the email body (plain text/HTML).
   - **Headers:** Parse the raw headers to extract `From`, `Reply-To`, `Subject`, `Received-SPF`, `DKIM-Signature`, `Authentication-Results`, and the `Received` chain.
   - **Attachments:** Iterate over attachments. For each, extract the `filename`, `mimeType`, `size` (in bytes), and generate a Base64-encoded string using `Utilities.base64Encode(attachment.getBytes())`.

### 4.2. Networking
Once the JSON payload is constructed, it is transmitted to the backend:
- **Backend URL:** The script will define a `BACKEND_URL` constant. For local development, this will be temporarily set to an **ngrok tunnel URL** pointing to the local Node.js server.
- **Transmission:** Use `UrlFetchApp.fetch(BACKEND_URL, options)` to execute an HTTPS `POST` request. The `options` MUST include an `Authorization` header.
- **Authorization:** For the MVP, the script will use `ScriptApp.getIdentityToken()` to fetch the Google Workspace user's identity token and pass it as `Bearer <token>`. This is mandatory to satisfy the backend's auth middleware stub.
- **Payload Format:** The extracted email data will be serialized as JSON (`payload: JSON.stringify(data)`) with the `Content-Type: application/json` header.
- **Error Handling:** A `try/catch` block MUST wrap the `UrlFetchApp.fetch()` call to catch network failures (e.g., a disconnected ngrok tunnel) and route them to the Error Card UI.
- **Response Handling:** The script will parse the incoming JSON response (containing `score`, `verdict`, and `signals`) and pass it to the UI Engine to render the Result Card.
