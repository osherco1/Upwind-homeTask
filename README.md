# Upwind Malicious Email Scorer

**An enterprise-grade Gmail Add-on providing transparent, explainable threat analysis.**

The Upwind Malicious Email Scorer is designed to intercept and analyze potentially malicious emails directly within the Google Workspace environment. By combining localized heuristic checks with robust, external Threat Intelligence, the tool offers end-users clear, actionable verdicts on email security.

---

## Architecture Overview

The system strictly enforces a **client-server separation of concerns**:

- **Frontend:** A lightweight Google Apps Script application utilizing the Gmail Card Service. It extracts raw email data (headers, bodies, attachments) and pushes payloads to the backend without executing any analytical logic locally.
- **Backend:** A hardened Node.js/TypeScript Express server. It handles payload validation, business logic, orchestration of Threat Intelligence API calls, and final score computation.
- **Tunneling:** A secure `ngrok` tunnel is utilized to expose the local Node.js environment to Google's cloud infrastructure for MVP testing and rapid development.

---

## The Scrutiny Engine (Core Signals)

The backend utilizes a triad of security signals to holistically evaluate threat levels:

### Signal 1: Metadata & Spoofing Detection
*Type: Local Heuristic Analysis*
- Validates the integrity of `Received-SPF` and `DKIM-Signature` headers.
- Identifies identity spoofing by detecting mismatches between `From` and `Reply-To` addresses.
- Scans the email body and subject for common social engineering and credential harvesting patterns (e.g., phishing urgency).

### Signal 2: Dynamic Sender Reputation
*Type: External API Enrichment*
- Performs real-time domain reputation checks against global threat feeds (e.g., VirusTotal API).
- Evaluates the historical trustworthiness and abuse reporting of the origin sender.

### Signal 3: Safe Attachment Analysis
*Type: Secure Hashing & Verification*
- Extracts Base64 attachment streams from the payload.
- Computes cryptographic SHA-256 hashes completely in-memory, ensuring **zero-disk-persistence** and eliminating execution risks.
- Verifies the hashes against global malware databases (VirusTotal) to detect known malicious files.

---

## Scoring Philosophy

Rather than relying on black-box heuristics, the scorer employs a **weighted average** approach. Each signal contributes a predefined weight to the overall risk profile:

- Metadata & Spoofing: **35%**
- Sender Reputation: **30%**
- Attachment Analysis: **35%**

The composite score maps directly to an explainable verdict:
- ✅ **Low Risk (0–29):** No significant threat indicators detected.
- ⚠️ **Medium Risk (30–59):** Suspicious elements present; proceed with caution.
- 🔶 **High Risk (60–84):** Strong indicators of phishing or spoofing.
- 🔴 **Critical Risk (85–100):** Confirmed malicious content or severe reputation warnings.

Every result returned to the user includes a detailed breakdown of these signals for full transparency.

---

## Technical Design Decisions

- **Zero Trust Architecture:** Every incoming payload is treated as untrusted. The API implements a rigorous schema validation layer. An authentication middleware stub is prepared for future JWT integration of the Google Workspace identity token.
- **Security-First Processing:** 
  - Strict payload size limits are enforced to protect against Denial of Service (DoS) attacks.
  - File processing is constrained to ephemeral Base64 streams for hashing, preventing arbitrary code execution.
- **Pragmatism:** Relying on `ngrok` for the MVP phase allows for unparalleled agility during local deployment without sacrificing the strict HTTPS requirements of Google Apps Script.

---

## Setup & Installation

### 1. Backend Setup

1. Navigate to the project root and install dependencies:
   ```bash
   npm install
   ```
2. Create a `.env` file based on the provided `.env.example`:
   ```bash
   cp .env.example .env
   ```
3. Populate the `.env` with your specific API key:
   ```env
   PORT=3000
   VIRUSTOTAL_API_KEY=your_virustotal_key_here
   ```
4. Start the development server:
   ```bash
   npm run dev
   ```

### 2. Tunneling Configuration

1. In a new terminal window, expose your local port 3000 using ngrok:
   ```bash
   ngrok http 3000
   ```
2. Copy the generated `https` forwarding URL (e.g., `https://<your-id>.ngrok-free.dev`).

### 3. Frontend Setup (Google Apps Script)

1. Navigate to [script.google.com](https://script.google.com/) and create a new project.
2. Open the **Project Settings** (gear icon) and check the box to **"Show 'appsscript.json' manifest file in editor"**.
3. Replace the contents of `appsscript.json` with the code provided in `frontend/appsscript.json`.
4. Replace the contents of `Code.gs` (or `קוד.gs`) with the code provided in `frontend/Code.gs`.
5. At the top of `Code.gs`, update the `BACKEND_URL` to point to your active ngrok tunnel and append the `/api/scan` path:
   ```javascript
   const BACKEND_URL = 'https://<your-id>.ngrok-free.dev/api/scan';
   ```
6. Click **Deploy** > **Test deployments** to install the Add-on in your Gmail account.

---

## Limitations & Roadmap

As an MVP, this project defines the foundational pipeline. Planned future enhancements include:
- **Full JWT Verification:** Upgrading the auth stub to rigorously decrypt and validate the cryptographic signatures of incoming Google Identity Tokens.
- **Persistent State:** Implementing a robust database layer to track scan history and construct persistent user whitelists/blacklists.
- **Machine Learning Integration:** Replacing static heuristic checks with dynamic Natural Language Processing (NLP) classifiers for advanced zero-day detection.
