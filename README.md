# 🛡️ Phishing Analyzer v0.6.2

**Email phishing analysis for security analysts, IT administrators, and incident responders.**

Phishing Analyzer inspects `.eml` messages and raw email headers, evaluates phishing indicators, correlates previously observed indicators of compromise (IOCs), and produces a unified **0–100 heuristic risk assessment**. It is available through a command-line interface (CLI), a FastAPI endpoint, and a web frontend. PDF reports include a visual risk dashboard followed by technical evidence.

**Web demo:** [https://demo.phishing-analyzer.com/](https://demo.phishing-analyzer.com/) — the deployed demo may be running a different version.

> **Analyst guidance:** The score is a heuristic, **not** a probability that an email is malicious or a guarantee that a low-scoring email is safe. Review the underlying evidence and any analysis limitations before making a security decision.

---

## 🚀 Features

### Unified phishing risk assessment

- Generates an overall **0–100 risk score** with **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL** verdicts.
- Separately scores five areas:
  1. Authentication
  2. Sender identity
  3. URLs and domains
  4. Social engineering
  5. Attachments and YARA
- Combines the components using weighted, bounded heuristics to reduce double-counting of related findings.
- Highlights noteworthy evidence and explains when parts of an analysis could not be completed or verified.
- Makes the assessment available to the terminal, the structured API response, the PDF report, and the local analysis history.

### Email parsing, headers, and sender analysis

- Accepts full **`.eml` messages** and **`.txt` files** containing raw email headers.
- Extracts message headers, bodies, MIME parts, attachments, and delivery (`Received`) hops.
- Examines `From`, `To`, `Reply-To`, and `Return-Path` domains for relevant differences.
- Identifies missing sender information, suspicious sender relationships, and possible internal impersonation indicators.
- Detects Microsoft 365 cross-tenant headers as **contextual information**, rather than automatically treating cross-tenant delivery as malicious.
- Includes MIME diagnostics and a detector for suspicious content appearing after a closing MIME boundary (BadEpilogue).

### SPF, DKIM, and DMARC interpretation

- Parses reported `Authentication-Results` and `Received-SPF` values, including SPF client IPv4/IPv6 addresses where present.
- Shows reported SPF, DKIM, and DMARC outcomes and relevant authentication domains.
- Identifies strict alignment where determinable and avoids guessing relaxed organizational-domain alignment.
- **Does not trust email-provided authentication headers by default.** Authentication results only affect risk scoring when the reporting receiver is explicitly configured as trusted.
- Clearly flags authentication evidence as **unverified** when a trusted receiving system has not been configured.

**Important:** Configure `TRUSTED_AUTH_SERVERS` only when you control the receiving mail gateway and know that it removes untrusted inbound `Authentication-Results` headers before adding its own. Merely matching a header's server name is not proof that the header is genuine.

### URL and domain analysis

- Extracts links from plain text and HTML, including `<a href>` destinations.
- Detects displayed-link / actual-destination domain mismatches.
- Checks for IP-address links, brand-like or misspelled domains, IDN/punycode and mixed-script homographs, and unusual URL userinfo or ports.
- Identifies URL shorteners, external redirect parameters, unusual paths, and suspiciously encoded destinations.
- Treats login-related vocabulary and certain TLDs as **weak supporting evidence**, not automatic proof of phishing.
- Performs URL-pattern analysis **without navigating to or downloading the linked destination**.
- Includes bounded DNS and RDAP lookups for sender-domain enrichment, subject to the available resolver and RDAP service.

### Social engineering detection

- Evaluates the email subject and body for social-engineering signals.
- Produces a separate **0–100 social-engineering score**, grade, summary, and matched trigger groups.
- Includes this score in the unified risk assessment.

### Attachments and embedded content

- Inspects actual attachment bytes, file signatures, MIME mismatches, and potentially dangerous or disguised extensions.
- Computes MD5, SHA-1, and SHA-256 hashes to support investigation and historical IOC correlation.
- Checks PDF content for JavaScript, automatic actions, embedded-file indicators, forms, external links, and related suspicious structures; deeper inspection uses `pypdf` when installed.
- Examines ZIP member names for macros, executable/script attachments, and other indicators without extracting or executing their contents.
- Inspects HTML, SVG, and script content for active code, credential forms, redirects, and obfuscation patterns.
- Can identify embedded PDFs and link-only PDF references; a **linked PDF is not treated as having been downloaded or byte-scanned**.
- Applies file-size and inspection limits to reduce resource exhaustion.

### YARA and MITRE ATT&CK

- Scans supported email components using YARA rules, including project-specific rules in `yara_rules`.
- Reports matched YARA rules and associated ATT&CK technique identifiers where defined.
- Maps detected indicators and applicable rule matches to MITRE ATT&CK output.

### Persistent local threat intelligence

- Uses a local **SQLite** database (`phish_analyzer/config/threat_intel.db`) to retain analysis history and observed IOCs.
- Correlates current sender, reply, return-path, IP, URL, and attachment indicators against historical observations.
- Records the completed assessment's overall risk score, social-engineering score, and verdict.
- Supports campaign tagging, campaign investigation, and IOC export in **JSON, CSV, and STIX** formats from the CLI.
- Can be disabled using `THREAT_INTEL_ENABLED=false`.

Historical IOC matches are investigative context; previous observation alone does not establish maliciousness.

### Reports, API, and web access

- Displays readable, ANSI-colored terminal findings and a text-based risk breakdown.
- Produces PDF reports with a dedicated **first-page risk dashboard**, colored component bars, key evidence, and assessment limitations. Subsequent pages contain mail-flow, message content, and technical output.
- Exposes `POST /analyze` through FastAPI for multipart file uploads, structured JSON responses, or downloadable PDF reports.
- Keeps the legacy `output` response field for existing frontend compatibility while adding structured findings and risk data.
- Supports concurrent API requests using request-local output capture, bounded analysis concurrency, and isolated temporary report files.
- Includes API-key validation and configurable cross-origin access.

---

## 📦 Installation

Requires **Python 3.12** for the supplied Docker image. For local development, use a Python version compatible with the project's `pyproject.toml` and installed dependencies.

```bash
git clone https://github.com/dacraven95/phishing-analyzer.git
cd phishing-analyzer
```

Create and activate a virtual environment (recommended):

```bash
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows PowerShell:
# .\venv\Scripts\Activate.ps1
```

Install the project:

```bash
python -m pip install .
```

Dependencies are defined in `pyproject.toml`. Deep PDF parsing requires `pypdf`. PDF HTML rendering uses Playwright/Chromium; if running outside the provided Docker image, ensure the required browser is installed:

```bash
python -m playwright install chromium
```

---

## 🔧 Command-line usage

Run these commands from the repository root (the directory containing `cli.py`). Do not run `phish_analyzer/core.py` directly; it uses package-relative imports.

```bash
# Analyze an email or raw header file
python cli.py -f suspicious.eml
python cli.py -f email_headers.txt

# Print structured findings and risk data in addition to diagnostic output
python cli.py -f suspicious.eml --json

# Include detailed MIME diagnostics
python cli.py -f suspicious.eml --mime

# Generate a PDF report
python cli.py -f suspicious.eml --report --output phish-report.pdf
```

**Note:** `--json` currently **prints a JSON section alongside the normal terminal analysis**. For a machine-consumable JSON response, use the FastAPI endpoint.

### Threat intelligence and campaign commands

```bash
# Show the 20 most recent analyses
python cli.py --list

# Show analyses associated with a campaign
python cli.py --list DocuSign-Spoof

# Tag an analysis by numeric ID
python cli.py --tag 7 DocuSign-Spoof

# Tag analyses containing an IOC
python cli.py --tag-indicator 203.0.113.10 DocuSign-Spoof

# List campaign names and counts
python cli.py --campaigns

# Show IOCs observed in a campaign
python cli.py --campaign-iocs DocuSign-Spoof

# Export all IOCs as JSON
python cli.py --export json

# Export one campaign as STIX
python cli.py --export stix --export-campaign DocuSign-Spoof

# Export CSV files to a selected directory
python cli.py --export csv --export-output ./exports

# Export one campaign as JSON
python cli.py --export json --export-campaign HR-Payroll-Phish --export-output ./exports
```

---

## 🌐 FastAPI and HTTP usage

Start the API from the repository root:

```bash
# Linux / macOS
export API_KEY="replace-with-a-long-random-secret"
python -m uvicorn api_main:app --host 127.0.0.1 --port 8000
```

On Windows PowerShell, set the variable with `$env:API_KEY = "..."` before starting Uvicorn.

The endpoint is **`POST /analyze`**; interactive API documentation is available at **`/docs`** when the API is reachable.

**An `API_KEY` must be configured.** With no configured key, the API returns HTTP `503`; with an invalid/missing request key, it returns HTTP `403`.

### JSON analysis

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: replace-with-your-configured-key" \
  -F "file=@suspicious.eml" \
  -F "show_mime=false"
```

The response includes:

| Field | Contents |
|---|---|
| `output` | Human-readable diagnostic output, kept for existing web clients |
| `risk_assessment` | Overall score, verdict, component scores, key evidence, limitations, and scoring method |
| `analysis_results` | Structured individual findings and their evidence |
| `details` | Additional scan information, such as attachments, YARA matches, and summarized correlations |
| `metadata` | Analyzed filename and timestamp |

### PDF analysis

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "X-API-Key: replace-with-your-configured-key" \
  -F "file=@suspicious.eml" \
  -F "create_pdf=true" \
  -o phish-report.pdf
```

The API accepts `.eml` and `.txt` uploads up to **25 MiB**, rejects empty files, and uses temporary request-specific files. Analysis requests may queue when the configured concurrent-analysis slots are occupied.

### Nginx / browser frontend

The web frontend can make same-origin requests through an Nginx reverse proxy, commonly at **`/api/analyze`**, which forwards to the FastAPI service's **`/analyze`** route. The public `/api/analyze` path is a **proxy configuration**, not an additional FastAPI route.

For a browser frontend, keep the API key on the **server/proxy**, not in browser JavaScript. Injecting a shared key at Nginx protects the secret from the browser, but **does not authenticate individual visitors**: the public reverse-proxy route must also have appropriate access controls, rate limits, and network restrictions.

If a separate website calls FastAPI across origins, set `CORS_ALLOWED_ORIGINS` to a comma-separated list of allowed origins. Same-origin proxy requests do not need CORS.

---

## 🐳 Docker deployment

The API Dockerfile installs the Python application and Chromium, then starts Uvicorn on port `8000`. The web frontend is served separately with Nginx.

Build the API image from the repository root:

```bash
docker build -t phish-analyzer-api:latest .
```

Then start it using your Docker Compose deployment. If your Compose file defines a `build:` section, you can rebuild and start with:

```bash
docker compose up -d --build
```

If Compose references only a prebuilt `image:`, rebuild the image separately as above, then recreate the API container so it uses the new image.

### Persistent SQLite and configuration

In the Docker image, the project's `phish_analyzer/config` directory resides at:

```text
/app/phish_analyzer/config
```

An example bind mount from a Compose file located in the repository root is:

```yaml
services:
  api:
    image: phish-analyzer-api:latest
    environment:
      API_KEY: ${API_KEY:?Set API_KEY before starting}
      THREAT_INTEL_ENABLED: "true"
    volumes:
      - ./phish_analyzer/config:/app/phish_analyzer/config
```

This mount is an **example for the API service**, not a replacement for your existing full Compose setup. Preserve your existing ports, Nginx service, networks, and other settings, and use the correct service name in Nginx's `proxy_pass`.

Before starting with a bind mount, ensure the host directory contains the files you intend to preserve, including `threat_intel.db` and `domain-whitelist.txt`. A bind mount hides the corresponding files bundled in the image; if you keep `version.txt` in that directory, include it on the host as well so report version lookup continues working. Back up SQLite using a database-aware backup procedure rather than copying a database that may be actively written.

### Environment settings

| Variable | Purpose | Default / behavior |
|---|---|---|
| `API_KEY` | Required API authentication secret | API refuses analysis if unset |
| `THREAT_INTEL_ENABLED` | Enables local SQLite threat-intelligence functionality | `true` |
| `TRUSTED_AUTH_SERVERS` | Comma-separated trusted Authentication-Results receiver IDs | Unset; authentication claims excluded from scoring |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed browser origins for direct cross-origin API requests | Empty; no cross-origin origins allowed |

Store secrets outside source control, such as in an excluded local `.env` file or an appropriate deployment secret-management system. Do not publish your production API key in frontend code, example configuration committed to Git, or a browser extension.

---

## 🧩 Project organization

Core analysis has been split into focused modules while retaining the existing CLI and API entry points:

```text
phishing-analyzer/
├── api_main.py                 # FastAPI endpoints, auth, upload/PDF handling
├── cli.py                      # CLI analysis and threat-intel operations
├── phish_analyzer/
│   ├── core.py                 # Analysis orchestration and compatibility helpers
│   ├── analysis_models.py      # Shared findings and AnalysisResult
│   ├── url_analysis.py        # URL, domain, and displayed-link checks
│   ├── auth_analysis.py       # Authentication header interpretation
│   ├── risk_scoring.py        # Unified risk assessment and terminal bars
│   ├── attachment_analysis.py # File/PDF/HTML/ZIP inspection
│   ├── pdfReport.py           # Dashboard and technical PDF report
│   ├── social_engineering.py  # Social engineering signals
│   ├── threat_intel.py        # SQLite IOC history and campaign functions
│   ├── yara_scanner.py        # YARA scanning
│   ├── attack_mapping.py      # MITRE ATT&CK output
│   └── config/                # Database, whitelist, and version data
└── ...                        # Additional frontend, packaging, and configuration files
```

`run_analysis_structured()` returns a shared `AnalysisResult`. The API serializes that result to JSON; PDF generation uses the same assessment and evidence. The legacy CLI and text-capture interfaces remain available for compatibility.

---

## 🧩 Browser sidebar extension

The project's existing README describes an optional Chromium-compatible sidebar extension distributed as `phish-analyzer-sidebar-packed.zip`.

If that package is included in your repository or release, extract it to a local folder, open `chrome://extensions` (or `brave://extensions`), enable **Developer mode**, and choose **Load unpacked**. Configure its API endpoint according to the extension's settings and your deployment's access controls.

The extension package and its compatibility with the current structured API were **not part of the files reviewed for this documentation update**.

---

## 🧪 Current limitations and planned improvements

These are **not yet documented as completed features**:

- **Optional LLM-assisted review:** Complement, not replace, deterministic phishing indicators with language-model reasoning and clear provenance.
- **Scoring calibration:** Evaluate thresholds and weights against a curated set of benign and malicious messages; reduce false positives and quantify detection performance.
- **Stronger domain/authentication validation:** Public Suffix List-aware organizational-domain comparisons and more complete trusted gateway verification.
- **Threat-intelligence reporting contract:** Standardize the correlation result schema and replace the remaining legacy threat-intel console formatter with structured output.
- **Richer web dashboard:** Render the existing structured API risk assessment and component scores directly in the frontend, similar to the PDF's visual overview.
- **Automated regression coverage:** Expand test fixtures for authentication, URL tricks, MIME anomalies, attachments, concurrency, PDF output, and API behavior.
- **Further sandboxing and resource controls:** Harden any HTML preview/browser rendering and expensive document inspection against untrusted or remote resources.

The **rule-based social engineering engine, unified 0–100 scoring, structured API responses, YARA/MITRE mapping, and visual PDF dashboard are already implemented** and are not listed as future features.

---

## 🔐 Security and privacy notes

- Treat submitted email files, attachments, email addresses, and extracted IOCs as **potentially sensitive**.
- The system inspects suspicious content; it does **not** guarantee that every attachment, URL, or displayed email body is safe.
- URL-pattern analysis does not intentionally visit suspicious links, but sender-domain DNS/RDAP enrichment uses network services, and HTML/PDF rendering has separate resource considerations.
- Restrict API access, protect the SQLite data directory and backups, and use TLS for remote deployments.
- The API key is a shared application secret, not a substitute for user-level authorization or edge access control.
- Verify external threat intelligence and scanner integrations before production use. Manually investigate significant findings.

---

## ⚖️ License

MIT License — free for personal, educational, and commercial use. See the repository's license file for the complete terms.

---

## ⭐ Acknowledgements

Phishing Analyzer began as a guided learning project in email forensics, phishing indicators, and secure coding. It continues to evolve into an extensible phishing-investigation toolkit for CLI, API, and browser-based workflows.
