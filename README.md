# 🛡️ Phishing Analyzer v0.5.2
### A lightweight command-line tool for analyzing email headers, email attachments, and identifying phishing indicators.

Phishing Analyzer helps security analysts, IT admins, and researchers inspect emails' attachments and headers for suspicious patterns such as SPF failures, domain mismatches, suspicious filetypes, and cross-tenant indicators.  

The project is intentionally built step-by-step, starting with header-only analysis and expanding toward full phishing detection (URLs, content scoring, attachment analysis, LLM analysis, FastAPI API, etc.).

You can view a live web demo running at: [https://demo.phishing-analyzer.com/](https://demo.phishing-analyzer.com/) `The demo's analyzer version may differ from current version`

---

## 🚀 Features

### ✔ YARA & MITRE
- Supports YARA & MITRE ATT&CK Rules
- Custom YARA rules added via the `yara_rules` folder

### ✔ Email Header Parsing
- Supports both **raw header text files** and full **`.eml`** email files.
- Automatically extracts the header block even if extra text appears before/after.

### ✔ Basic Email Attachment Analysis
- Analyzes attachments based on **actual content**, not filenames alone.
- Detects **embedded scripts**, inline SVG, and hidden active payloads.
- Flags **obfuscated JavaScript loaders** commonly used in phishing emails.

### ✔ SPF Analysis
- Parses **multiple `Received-SPF` headers**.
- Uses the **most recent hop** (closest to your system) for evaluation.
- Extracts:
  - SPF result (`pass`, `fail`, `softfail`, etc.)
  - Sending IP (`client-ip=...`)

### ✔ Cross-Tenant Detection
- Detects any header containing `"crosstenant"` (case-insensitive).
- Indicates Microsoft 365 cross-tenant hops.

### ✔ Domain Extraction
Extracts and compares domains from:
- `From`
- `Reply-To`
- `Return-Path`

### ✔ Local Threat Intel DB Memory
- Uses a `sqlite3` db file to store IOCs longterm
- Alerts you in the cli output if an IOC has been seen
- Ability to search through intel via cli flags
```bash
# Analyze an email as normal — IOCs saved automatically
python cli.py -f suspicious.eml

# List your 20 most recent analyses
python cli.py --list

# List analyses for a specific campaign
python cli.py --list DocuSign-Spoof

# Tag a single analysis by its ID
python cli.py --tag 7 DocuSign-Spoof

# Tag every analysis that contains a specific indicator
python cli.py --tag-indicator 0.0.0.0 DocuSign-Spoof

# View all campaign tags and counts
python cli.py --campaigns

# Dump every IOC associated with a campaign
python cli.py --campaign-iocs DocuSign-Spoof
```
- Export Threat Intel to JSON or CSV
```bash
# Export everything as JSON
python cli.py --export json

# Export a specific campaign as STIX for sharing with your SOC
python cli.py --export stix --export-campaign DocuSign-Spoof

# Export all domains and hashes as CSV into a specific folder
python cli.py --export csv --export-output ./exports

# Export a campaign as JSON to a specific folder
python cli.py --export json --export-campaign HR-Payroll-Phish --export-output ./exports
```

Detects Cyrillic Characters & Flags mismatches that often occur in phishing emails.
```bash
Domain contains Cyrillic characters
    evidence: р(p)а(a)ypal.com
```

### ✔ Terminal Output Enhancements
- Colored output using ANSI escape codes.
- Optional ASCII banner at startup.

### ✔ PDF Output
- Easy to read PDF which includes terminal output
- Can return the PDF via the API for automated workflows
- PDF generation uses `-r` via `cli.py` or by setting `create_pdf = True` in API body

### ✔ Safe for GitHub
- `.gitignore` included to prevent committing sensitive `.eml` or header samples.

### ✔ Browser Extension Available
You can download the `phish-analyzer-sidebar-packed.zip` file and unzip it to use as a browser sidebar extension.
* Unzip to a local folder (e.g. MyAwesomeChromeExtension)
* open `chrome://extensions` or `brave://extensions` and enable "developer mode"
* click on "load unpacked" and point to unzipped folder
* enable extension if needed.
* Open extension from the extension menu of browser

Can point extension to your own local copy of the phishing-analyzer API `(default is the live demo API)`

---

## 📦 Local Installation

Clone the repository:

```bash
git clone https://github.com/dacraven95/phishing-analyzer.git
cd phish-analyzer
```

(Optional) Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

The tool uses a few dependencies which can be installed from the `pyproject.toml` file by running:
```bash
pip install .
```

---

## 🔧 CLI Usage

### Analyze a file (header txt or eml)

```bash
python cli.py -f email_headers.txt
python cli.py -f email.eml
```
Or to generate the terminal output into a PDF report as your output:
```bash
python cli.py -f email.eml -r -o my-report.pdf
```
Note: `PDF generation is still a new feature and the report mainly just shows a formatted terminal output.`

### Dockerbuild + Docker Compose

You can build the docker container locally which exposes this tool as an API on your local network
```bash
docker build phish-analyzer-api .
```

The API has a single endpoint `<your-ip>:8000/analyze` which returns the entire terminal output or the PDF report document.

The API docs are viewable at `<your-ip>:8000/docs` once you spin up the container.

## Example curl command
```bash
curl -X POST https://your-server/analyze \
  -H "X-API-Key: your-secret-key-here" \
  -F "file=@email.eml"
```

---

## 📄 Example Output

```
===========================================
   PHISH ANALYZER - Email Header Scanner
===========================================

[+] Detected EML file

[+] Email attachments detected
- {'filename': 'bad-attachment.virus', 'content_type': 'text/plain', 'size': 1234}
-- Potentially risky filetype detected => .virus

From:        "Example Sender" <alerts@sample.com>
Reply-To:    noreply@marketing-platform.com>
Return-Path: <bounce@mailer.sendgrid.net>

From domain:        sample.com
Reply-To domain:    marketing-platform.com
Return-Path domain: mailer.sendgrid.net

SPF Result:         fail
Client IP:          192.168.1.1

CrossTenant:        True
```

---

## 🧪 Roadmap / Future Enhancements

### 🔜 Coming Soon

* Suspicious content rule engine
* LLM-based tone/intent scoring
* Full risk scoring engine (0–100)
* JSON output mode

---

## ⚖️ License

MIT License — free for personal, educational, and commercial use.

---

## ⭐ Acknowledgements

This project began as a guided, step-by-step learning exercise to understand email forensics, phishing indicators, and secure coding practices.
It will continue evolving into a full-featured phishing analysis toolkit.