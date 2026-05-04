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

## APIs Used

The scorer integrates with a focused set of external services to balance analytical depth against operational simplicity:

- **VirusTotal API** — Leveraged across two distinct security signals:
  - *Domain / IP Reputation:* Real-time queries against the originating sender's domain and IP infrastructure to surface known abuse history and threat-feed matches.
  - *Attachment Analysis:* Verification of attachment SHA-256 hashes against global malware corpora to identify previously catalogued malicious files.
- **Google Workspace / Gmail Card Service APIs** — Powers the native Add-on interface. Responsible for rendering the analysis card directly within Gmail, accessing the active message context, and extracting the raw email payload (headers, body, attachments) that the backend consumes.

---

## Implemented Features

- **Email Content & Metadata Analysis** — Validates `Received-SPF` and `DKIM-Signature` header integrity, compares the `Reply-To` address against `From` to surface identity spoofing, and applies semantic / heuristic pattern matching across the subject and body to flag credential harvesting and social engineering language.
- **Dynamic Enrichment (Sender Reputation)** — Evaluates the originating IPs and domains against external threat intelligence feeds via the VirusTotal API, producing a real-time reputation signal grounded in globally aggregated abuse data.
- **Attachment Analysis (MVP)** — Safely extracts attachments purely in-memory from the Base64 payload, generates cryptographic SHA-256 hashes, and checks them against external APIs **without ever writing to disk**, preserving a zero-disk-persistence guarantee.
- **Weighted, Explainable Scoring** — Composes the three signals into a transparent weighted score (Metadata 35% / Reputation 30% / Attachments 35%) mapped to a four-tier verdict (Low / Medium / High / Critical), with the per-signal breakdown surfaced back to the end user.
- **Hardened Request Pipeline** — Strict schema validation, payload size constraints, and a static API key gate enforced on every inbound request to the `/api/scan` endpoint.

---

## Scoring Philosophy

Rather than relying on black-box heuristics, the scorer employs a **weighted average** approach. Each signal contributes a predefined weight to the overall risk profile:

- Metadata & Spoofing: **35%**
- Sender Reputation: **30%**
- Attachment Analysis: **35%**

The composite score maps directly to an explainable verdict:
- **Low Risk (0–29):** No significant threat indicators detected.
- **Medium Risk (30–59):** Suspicious elements present; proceed with caution.
- **High Risk (60–84):** Strong indicators of phishing or spoofing.
- **Critical Risk (85–100):** Confirmed malicious content or severe reputation warnings.

Every result returned to the user includes a detailed breakdown of these signals for full transparency.

---

## Technical Design Decisions

- **Zero Trust Architecture:** Every incoming payload is treated as untrusted. The API enforces a rigorous schema validation layer at the boundary, and an authentication middleware stub is prepared for future JWT integration of the Google Workspace identity token.
- **Security-First Processing:**
  - Strict payload size limits guard against resource-exhaustion vectors.
  - File processing is constrained to ephemeral Base64 streams for hashing, preventing arbitrary code execution and eliminating the need for disk I/O.
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

## Limitations

The MVP intentionally scopes a tight, defensible perimeter. The following constraints reflect deliberate architectural trade-offs rather than oversights — each is a known boundary slated for hardening before any production rollout:

- **Rate Limiting (Security & Scalability):** The `/api/scan` endpoint does not currently enforce per-client or global rate limits. In its present form the service is exposed to brute-force probing of the API key gate and to denial-of-service pressure under sustained traffic. A token-bucket or sliding-window limiter (per-IP and per-identity) is the immediate next layer of defense.
- **Statelessness (No Persistence Layer):** The backend is intentionally stateless — there is no database backing scan history, audit trails, or user-managed allow / blocklists. Every request is evaluated in isolation, which simplifies the security surface but precludes longitudinal threat tracking, repeat-offender detection, and tenant-specific policy.
- **Attachment Analysis Depth:** True deep-file inspection (unpacking, dynamic execution, behavioral analysis) requires a fully isolated **sandbox environment** to contain the execution risk inherent in detonating untrusted binaries. The MVP deliberately compromises by restricting analysis to **in-memory SHA-256 hashing and reputation lookups**, preserving a zero-trust, zero-disk-persistence posture without taking on sandbox infrastructure overhead. Files unknown to global threat feeds will therefore pass the attachment signal regardless of latent malicious behavior.
- **Authentication:** Inbound requests are gated by a **static API key stub** rather than a fully verified Google Identity Token. The middleware seam for full JWT validation — cryptographic signature verification, audience / issuer checks, and per-user identity binding — is in place but not yet wired to Google's public key endpoints.

---

## Roadmap

Planned hardening passes that directly address the limitations above:
- **Full JWT Verification** — promote the auth stub to rigorously validate Google Identity Token signatures, audience, and expiry on every request.
- **Persistent State** — introduce a database layer for scan history, audit logs, and per-user allow / blocklists.
- **Rate Limiting & Abuse Controls** — per-identity and per-IP throttling at the edge of `/api/scan`.
- **Machine Learning Integration** — augment static heuristics with NLP classifiers for zero-day phishing patterns.