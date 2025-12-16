# 🛡️ Phishing Analyzer v0.4.4
### A lightweight command-line tool for analyzing email headers and identifying phishing indicators.

Phishing Analyzer helps security analysts, IT admins, and researchers inspect email headers for suspicious patterns such as SPF failures, domain mismatches, and cross-tenant indicators.  

The project is intentionally built step-by-step, starting with header-only analysis and expanding toward full phishing detection (URLs, content scoring, LLM analysis, FastAPI API, etc.).

---

## 🚀 Features (Current)

### ✔ Email Header Parsing
- Supports both **raw header text files** and full **`.eml`** email files.
- Automatically extracts the header block even if extra text appears before/after.

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

Flags mismatches that often occur in phishing emails.

### ✔ Terminal Output Enhancements
- Colored output using ANSI escape codes.
- Optional ASCII banner at startup.

### ✔ Safe for GitHub
- `.gitignore` included to prevent committing sensitive `.eml` or header samples.

---

## 📦 Installation

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

## 🔧 Usage

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

---

## 📄 Example Output

```
===========================================
   PHISH ANALYZER - Email Header Scanner
===========================================

[+] Detected EML file
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

* HTML + text body extraction - ✔
* URL detection - ✔
* Domain reputation heuristics - ✔
* Suspicious content rule engine
* LLM-based tone/intent scoring
* FastAPI REST API endpoint - ✔
* Full risk scoring engine (0–100)
* JSON output mode

---

## ⚖️ License

MIT License — free for personal, educational, and commercial use.

---

## ⭐ Acknowledgements

This project began as a guided, step-by-step learning exercise to understand email forensics, phishing indicators, and secure coding practices.
It will continue evolving into a full-featured phishing analysis toolkit.