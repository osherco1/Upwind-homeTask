## Section 1 — System Identity & Purpose
The Upwind Malicious Email Scorer is a stateless, client-server system designed to intercept and analyze potentially malicious emails within Google Workspace. It consists of a thin Google Apps Script frontend (Gmail Add-on) that extracts raw email data and a hardened Node.js/TypeScript backend that orchestrates threat intelligence analysis. The system provides transparent, explainable threat verdicts based on localized heuristics and external API lookups (e.g., VirusTotal).
The primary outputs of the system are the computed JSON threat assessment returned by the backend and the visual Result Card rendered in the Gmail UI.
The data/state model is strictly in-memory and ephemeral; no attachments or email data are saved to disk, and no persistent database exists in the MVP.
Persistent state files: `[MISSING]`.
Agent-facing invariant files: `[MISSING]`.

## Section 2 — Repository Topology
```text
.
├── DESIGN.md
├── FRONTEND_PLAN.md
├── README.md
├── frontend/
│   ├── Code.gs
│   └── appsscript.json
├── package.json
├── src/
│   ├── middlewares/
│   │   ├── auth.ts
│   │   └── validateRequest.ts
│   ├── routes/
│   │   └── scanRouter.ts
│   ├── server.ts
│   └── services/
│       ├── signal1.ts
│       ├── signal2.ts
│       └── signal3.ts
└── tsconfig.json
```

| Path | Type | Agent Action | Notes |
|---|---|---|---|
| `frontend/Code.gs` | Source | Edit | Contains purely UI generation and payload extraction logic. |
| `frontend/appsscript.json` | Config | Read | Manifest file defining Google Workspace Add-on scopes. |
| `src/routes/scanRouter.ts` | Source | Edit | Defines the `POST /api/scan` endpoint and composite scoring logic. |
| `src/services/*.ts` | Source | Edit | Contains isolated logic for the three core analysis signals. |
| `DESIGN.md` | Doc | Read | Contains the authoritative JSON payload contracts. |

Filename / naming convention patterns:
- Source files: `*.ts` (Backend), `*.gs` (Frontend).
Derived ID / slug formats: `[MISSING]`.

## Section 3 — Component Matrix
| Module/Skill Name | Invocation | Primary Input | Primary Outputs | State Written | Forbidden Actions |
|---|---|---|---|---|---|
| `frontend/Code.gs` | User clicks "Scan Email" | `e.gmail.messageId` | HTTP POST JSON payload | `[NONE]` | Executing Node.js code or scoring logic. |
| `src/middlewares/auth.ts` | Express routing | Request Headers | Next() or 401 | `[NONE]` | Leaking identity tokens. |
| `src/middlewares/validateRequest.ts` | Express routing | Request Body | Validated Body or 400 | `[NONE]` | Modifying payload structure. |
| `src/routes/scanRouter.ts` | `POST /api/scan` | Validated JSON payload | JSON verdict response | `[NONE]` | Saving attachments to disk. |
| `src/services/signal1.ts` | `analyzeMetadata()` | Email headers & body | Sub-score & details | `[NONE]` | Making external network requests. |
| `src/services/signal2.ts` | `checkSenderReputation()` | Sender Domain / IP | Sub-score & details | `[NONE]` | Ignoring API timeouts. |
| `src/services/signal3.ts` | `analyzeAttachments()` | Base64 attachments | Sub-score & details | `[NONE]` | Writing decoded bytes to filesystem. |

Differences between module variants: `signal1.ts` executes entirely locally (synchronous), whereas `signal2.ts` and `signal3.ts` orchestrate asynchronous external API lookups.
Invocation example: `analyzeMetadata(req.body)`

## Section 4 — State Architecture & Mutation Rules
The canonical execution cycle is entirely stateless: Read request → Validate payload → Compute (Mutate) in-memory scores → Write (Emit) JSON response.
Persistent State File / Database Table: `[MISSING]`.
Cross-module symmetry rules: If an email contains no attachments, Signal 3 is N/A, and its 35% weight is redistributed proportionally across Signal 1 and Signal 2.
Audit trail mechanism: `[MISSING]`.

⚠️ INVARIANT: The backend must never write decoded attachment bytes to the filesystem. Violation = Arbitrary code execution vulnerability.
⚠️ INVARIANT: The frontend must perform zero analysis or scoring logic. Violation = Broken separation of concerns.

## Section 5 — Pipeline / Execution Stages
1. **Ingest (Frontend):** The Gmail Add-on extracts the email body, headers, and Base64-encoded attachments.
2. **Transmit (Frontend):** The Add-on sends a structured JSON payload via `POST /api/scan` to the backend.
3. **Validate (Backend):** `validateRequest.ts` sanitizes the payload.
4. **Analyze (Backend):** The three signal services compute independent sub-scores (0-100).
5. **Score (Backend):** `scanRouter.ts` calculates a weighted composite score and determines the human-readable verdict.
6. **Emit (Backend):** A JSON response containing the score, verdict, and signal breakdown is returned.
7. **Render (Frontend):** The Add-on displays the Result Card with color-coded verdicts.

Quality gates: The payload must pass `validateRequest.ts` before any signal processing occurs. Typescript compilation (`npm run build`) must pass before deployment.
Dry-run / preview mode: `[MISSING]`.

## Section 6 — Input Contracts
Expected input format (JSON Payload to `/api/scan`):
```json
{
  "body": "<string>",
  "headers": {
    "from": "sender@example.com",
    "replyTo": "reply@example.com",
    "subject": "Urgent: Verify your account",
    "receivedSpf": "pass",
    "dkimSignature": "<raw DKIM header>",
    "authenticationResults": "<raw auth-results header>",
    "receivedChain": ["from mail-server.example.com (192.0.2.1) ..."]
  },
  "attachments": [
    {
      "filename": "invoice.pdf",
      "mimeType": "application/pdf",
      "size": 204800,
      "contentBase64": "<Base64-encoded content>"
    }
  ]
}
```
Optional input types: `[MISSING]`.
Error handling: If external APIs timeout or rate limits are hit in Signal 2/3, the signal returns a neutral score (50) and flags as `"inconclusive"`. If the API key is missing, the signal is skipped and weights are adjusted.
External resource access policy: VirusTotal API is called on-demand with strict timeouts to prevent hanging responses.

## Section 7 — Output Contracts
Output artifact type: JSON HTTP Response.
Required structure:
```json
{
  "score": 78,
  "verdict": "High Risk",
  "signals": [
    {
      "name": "Metadata & Spoofing",
      "score": 85,
      "details": "SPF check failed. Subject contains urgency pattern."
    }
  ]
}
```
Markdown outputs: `[MISSING]`.
JSON / structured outputs: The top-level keys `score`, `verdict`, and `signals` are strictly mandatory.
Append-only fields in output artifacts: `[MISSING]`.

## Section 8 — Disambiguation & Anti-Hallucination Rules
1. **Fabricating Schema Fields:** Do not invent properties like `isMalicious` or `threatLevel` in the API contracts. Correct agent behavior: Strictly adhere to the `score`, `verdict`, and `signals` schema defined in `DESIGN.md`.
2. **Persistent State Assumptions:** Do not attempt to read from or write to a database or local filesystem. Correct agent behavior: Treat the backend as completely stateless; all hashing and scoring is done in-memory.
3. **Frontend Analysis Logic:** Do not add regex or reputation logic to `Code.gs`. Correct agent behavior: Place all analytical logic exclusively in the Node.js `src/services/` directory.
4. **Executing Attachments:** Do not pass attachment buffers to execution contexts or external libraries that write to disk. Correct agent behavior: Use crypto modules to hash the buffer directly in-memory.

**When Uncertain, Do This:**
- Halt and surface the ambiguity to the user.
- Cite the specific file and line creating the uncertainty.
- Propose the minimally invasive safe action.
- Do not proceed until the user confirms.

## Section 9 — Quick-Reference Cheat Sheet
| Task | Correct Module/Skill | Key Flag/Option |
|---|---|---|
| Updating scoring weights | `src/routes/scanRouter.ts` | `compositeScore` calculation |
| Adding local heuristic checks | `src/services/signal1.ts` | `analyzeMetadata` |
| Changing Add-on UI | `frontend/Code.gs` | CardService builder |

State file paths: `[MISSING]`
Schema file paths: `DESIGN.md`
Primary quality-gate commands: `npm run build`
Core state mutation invariant: All data processing is strictly ephemeral and in-memory.
Escalation rule: If a required file is [MISSING], halt and surface the gap to the user before proceeding.
