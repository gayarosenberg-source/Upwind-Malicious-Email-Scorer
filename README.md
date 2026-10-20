# Upwind-Malicious-Email-Scorer
A real-time Gmail Security Add-on that detects phishing and malicious emails using a custom Python risk-scoring engine.

## 1. Project Objective & Target Audience
The Upwind Malicious Email Scorer is a B2B security solution engineered for enterprise environments. Unlike consumer anti-spam filters that rely on volume-based heuristics, corporate security must counter highly targeted threats like Business Email Compromise (BEC), executive spoofing, and vendor impersonation. To address this, the project implements a multi-layered rule engine and scoring matrix that conducts granular inspections of intent indicators—such as subtle domain mismatches, urgency cues, and hidden redirects—directly within the corporate user's inbox workflow.

## 2. Process & Execution

### Step 1: Formulating Detection Rules
To build a robust heuristic engine, nine discrete analysis rules were designed to target specific social engineering vectors:
* **Domain Spoofing:** Checks if the sender's display name contains sensitive organizational roles (e.g., CEO, CFO, HR, Admin, Security) while originating from an external, non-corporate domain.
* **Combined Financial Urgency:** Scans the subject and body for urgency keywords alongside financial terms or currency symbols (`$`, `€`, `₪`). Applies a severe risk multiplier if both contexts occur simultaneously, and a moderate score if only one context is found.
* **Suspicious URL Patterns:** Inspects all embedded hyperlinks for known phishing keywords (e.g., "login", "secure", "verify"), commercial URL shorteners (e.g., bit.ly, tinyurl), or raw IPv4 addresses.
* **Spam & Geo TLDs:** Flags originating domains that use low-cost, commonly abused top-level domains (e.g., `.xyz`, `.top`, `.tk`) or specific country codes not typical for routine organizational business (e.g., `.ru`, `.ir`, `.kp`).
* **Reply-To Mismatch:** Compares the 'From' address header with the 'Reply-To' header. Triggers a high-severity alert if they differ, indicating potential address spoofing intended to misdirect replies.
* **Dangerous Attachments:** Flags files utilizing double extensions (e.g., invoice.pdf.exe) designed to trick users relying on default operating system file-extension masking.
* **Communication History & Sender Reputation:** Evaluates the historical relationship with the sender, as targeted phishing typically originates from unknown addresses. To maintain strict data privacy, the current PoC uses a mocked "First-Time Sender" flag to demonstrate how this lack of prior communication increases the threat score.
* **Typosquatting Detection:** Uses the `difflib` sequence matching algorithm to detect external domains that are visually highly similar (>80% similarity ratio) to the protected corporate domain.
* **Homograph Attacks / Punycode:** Flags domain names utilizing Internationalized Domain Names (IDNs) with xn-- prefixes, which obscure non-ASCII characters used to imitate legitimate domain names.

### Step 2: Risk-Scoring Matrix
The scoring model is a two-dimensional Risk Matrix:

`Threat Score = Impact Score * Confidence Score`

* **Impact:** Severity of potential damage if the threat succeeds (Scale 1–10).
* **Confidence:** Analytical certainty that the indicator represents malicious intent (Scale 1–10).

Final aggregated scores are mapped to risk tiers:
* **LOW (0–29):** Informational indicators only; likely safe.
* **MEDIUM (30–59):** Caution advised; non-standard headers or external links present.
* **HIGH / CRITICAL (60-100):** Severe social engineering signatures detected; immediate warning rendered.

### Step 3: Telemetry & Business Intelligence
For enterprise Security Operations Centers (SOCs), isolated user alerts are insufficient. The backend was extended to automatically append telemetry records to a daily log CSV whenever an evaluated email crosses the configurable threat threshold. This structured export provides raw data for SIEM ingestion, SOC dashboards, and trend analysis across the organization.

### Step 4: Python Backend Implementation
The detection logic was constructed as a Flask service in Python. To ensure long-term maintainability and software engineering discipline, the rule framework follows a strict modular design:
* Each rule operates as an isolated function returning a standardized result dictionary (rule_id, triggered, impact_score, confidence_score, details).
* The execution controller aggregates results by appending output to a rules_results list.
* Adding, modifying, or deprecating a detection rule requires zero structural changes to the core evaluation loop or API interface layer.

### Step 5: Security and Authentication
To secure communication between the Google Apps Script frontend and the local Python service, an API authentication token header (X-Upwind-Auth) was implemented. Requests lacking the matching authorization token are rejected at the edge with HTTP 401 Unauthorized.

### Step 6: Integration & Deployment
Connecting the cloud-hosted Gmail interface to the local development environment involved:
* Developing a lightweight Google Apps Script (Code.gs and appsscript.json) manifest defining contextual trigger handlers for the Gmail UI.
* Exposing the local Flask server on port 5000 via ngrok HTTP tunneling.
* Updating the backend fetch URL inside Code.gs with the active HTTPS ngrok endpoint.

### Step 7: Quality Assurance
The engine underwent validation testing using a test suite of synthesized BEC lures, spoofed header payloads, punycode strings, and clean everyday business correspondence to refine scoring thresholds and eliminate false-positive loops.

### Step 8: Version Control
The codebase was structured into logical directories (backend service, frontend appscript, documentation), sanitized of environment credentials, and committed to a clean GitHub repository.

## 3. Quick Start & Execution
To run and evaluate the Add-on locally:

**Backend (Python Engine)**
1. Install dependencies: `pip install flask`
2. Start the risk-scoring engine: `python app.py` (Defaults to `port 5000`).
3. Establish a secure tunnel: `ngrok http 5000`

**Frontend (Google Apps Script)**
1. Create a new Google Apps Script project and paste the contents of `Code.gs` and `appsscript.json`.
2. Important: Update the `API_BASE_URL` variable in `Code.gs` with your active ngrok HTTPS URL.
3. Deploy as a Workspace Add-on (`Deploy > Test deployments > Install`) and open any email in Gmail to trigger the analysis.

## 4. Product Decisions, Trade-offs & Future Enhancements

| Feature / Area | Implementation Choice | Rationale & Trade-off | Future Production State |
|---|---|---|---|
| **Content Analysis** | Static Heuristics & RegEx | Avoided heavyweight NLP/AI models to minimize runtime latency and external API dependencies during the MVP phase. | Integrate zero-shot LLM classifiers to analyze tone, semantic urgency, and conversational anomalies. |
| **Sender History (Rule 7)** | Client-Side Flag Mocking | Adheres to the Principle of Least Privilege. Calculating this locally avoids granting the backend broad API scopes to read user mailboxes, minimizing privacy surface and compliance overhead (GDPR/SOC2). | Query an enterprise Graph API / SIEM database that tracks organization-wide communication metadata. |
| **Interactive AI Security Assistant** | UI Placeholder ("Ask Internal AI" Button) | The "Ask AI" button was added to outline the product vision, but backend integration was deferred to avoid scope creep and external data leakage risks during the PoC. | Connect the interface to a private, enterprise-secured LLM (e.g., local model or Vertex AI) allowing users to securely converse with the AI about threats without exposing corporate data. |
| **Keyword Management** | Hardcoded Target Lists | List arrays for financial and urgency terms are stored directly within rule modules for high-speed execution. | Move wordlists to remote database Lookup Tables managed dynamically by SOC administrators. |
| **Subdomain Handling** | Strict Domain Matching | Subdomains (e.g., mail.upwind.com) that do not exactly match the base domain are flagged as external. | Implement public suffix parsing (tldextract) to distinguish valid corporate subdomains from third-party services. |
| **Advanced Typosquatting** | difflib Similarity Scoring | Catches basic visually similar domains but bypasses complex multi-level evasion (e.g., upwind.com.attacker.io). | Incorporate full tree-based string parsers and DNS WHOIS registration age checks. |
| **Threat Matrix Expansion** | Core 9 Vectors implemented | A time-boxed PoC required focusing on the highest-probability corporate vectors (e.g., BEC, Typosquatting). | Conduct continuous threat intelligence research to cover emerging vectors like QR code phishing (Quishing) and zero-day evasions. |
| **Workspace Integrations** | Scoped strictly to Gmail UI | The assignment specified an email scorer, so development was isolated to the Gmail Add-on context. | Expand the Add-on's reach across the Google Workspace ecosystem, inspecting Calendar invites (meeting link phishing) and shared Drive files for a holistic security posture. |
| **Contextual Risk via Cloud IAM (Upwind Synergy)** | Flat risk scoring (All users treated equally) | Currently, an attack on a guest user receives the same score as an attack on the CEO, lacking target-value context. | Integrate with Upwind's core CNAPP/IAM data: dynamically increase the Impact score if the targeted employee holds high-privilege cloud architecture access (e.g., AWS root). |
| **Campaign Correlation Engine** | Isolated Email Evaluation | The engine evaluates threats in a vacuum, treating each email as a separate incident and missing coordinated attacks. | Ingest logs into a Graph Database to identify attack clusters and visualize lateral threat campaigns targeting multiple departments over time. |
| **Identity Provider (IdP) Integration** | Hardcoded role arrays (e.g., "CEO", "CFO") | A PoC relies on static lists. In production, hardcoding roles is unscalable and misses mid-level targeted employees. | Integrate with Azure AD, Google Workspace Directory, or Okta to dynamically cross-reference sender names against the actual corporate employee directory. |
| **Cloud Tenant Verification (CSPM Synergy)** | Generic URL keyword analysis | The engine flags general suspicious words (e.g., "login") but lacks context regarding the organization's actual cloud infrastructure. | Cross-reference external links against Upwind's Cloud Security Posture Management (CSPM) inventory to flag fake AWS/Azure login portals not owned by the company. |
| **Risk Scoring Algorithm** | Static Heuristic Multiplication | A linear `Impact * Confidence` formula is transparent and fast for an MVP, but struggles to calculate accurate aggregate probabilities for complex, overlapping threat indicators. | Transition to a probabilistic Machine Learning model (e.g., Bayesian Networks) trained on historical SOC data to dynamically adjust weights, calculate statistical likelihoods, and reduce false positives. |
| **Event Deduplication (Idempotency)** | Stateless Telemetry Logging | The MVP logs every request crossing the risk threshold. Gmail UI triggers often fire multiple times per email view, causing duplicate CSV records. A stateful cache was excluded from the PoC. | Implement an idempotency key mechanism using an in-memory datastore (e.g., Redis) to track processed `messageId`s and prevent duplicate logging for the same email event. |
