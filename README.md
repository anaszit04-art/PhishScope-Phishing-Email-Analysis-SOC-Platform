
# PhishScope v1.0

PhishScope is a Python-based, defensive phishing email investigation
platform designed for security research, education, and SOC workflows.

It analyzes locally stored email evidence, extracts indicators of
compromise (IOCs), correlates URLs with a downloaded OpenPhish feed,
and generates explainable investigation reports.

The project includes a local Streamlit SOC dashboard.

## Features

- Offline `.eml` email analysis
- Email header inspection
- Reported SPF, DKIM and DMARC observations
- URL and hostname IOC extraction
- Suspicious HTML link comparison
- IP-based URL identification
- Offline recorded redirect-chain analysis
- OpenPhish URL intelligence correlation
- Exact, normalized and hostname-level matching
- MITRE ATT&CK candidate mapping
- Explainable heuristic risk scoring
- SHA-256 evidence preservation
- JSON case reporting
- SOC dashboard
- Analyst notes and case status tracking
- Case event timelines
- TXT and JSON analyst exports
- Report structural validation

## Requirements

- Python 3.14 (tested environment)
- Kali Linux (tested environment)
- Python virtual environment
- Dependencies listed in `requirements.txt`

Other operating systems may work but have not been verified.

## Installation

Clone the repository and enter the project directory.

```bash
git clone <YOUR_REPOSITORY_URL>
cd PhishScope

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -r requirements.txt
```

Replace `<YOUR_REPOSITORY_URL>` with your actual repository URL.

## Download phishing URL intelligence

```bash
python src/feed_loader.py
```

This downloads the OpenPhish URL feed into `data/feeds/`.

Downloading feed data is a network operation. Investigation
and correlation against an existing local feed are offline.

## Analyze a local email

```bash
python main.py \
  --email data/emails/advanced_test.eml \
  --feed data/feeds/openphish.txt
```

The sample files under `data/` are local laboratory fixtures
and are not necessarily distributed with a public repository.

A successful run creates a JSON case report in `reports/`.

## Import email evidence

```bash
python -m src.evidence_importer \
  --email /actual/path/to/sample.eml \
  --source "Authorized email sample"
```

Use the returned imported evidence path when running `main.py`.

Only import email files you are authorized to investigate.

## Run the SOC dashboard

```bash
python -m streamlit run dashboard.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --browser.gatherUsageStats false
```

Open `http://127.0.0.1:8501` inside the Kali VM.

The dashboard is designed for local use and has no
user-authentication or authorization system.

Do not expose it to the public Internet.

## Run automated tests

```bash
python -m pytest tests/ -q
```

## Run release verification

```bash
python release_check.py
```

This runs the test suite and a synthetic end-to-end
investigation using temporary evidence and report directories.

## Major components

| File | Responsibility |
| --- | --- |
| `main.py` | Investigation orchestration |
| `src/feed_loader.py` | OpenPhish feed acquisition |
| `src/ioc_extractor.py` | URL IOC extraction |
| `src/email_analyzer.py` | Email parsing |
| `src/advanced_detector.py` | Detection rules |
| `src/redirect_analyzer.py` | Offline redirect evidence |
| `src/mitre_mapper.py` | ATT&CK candidate mapping |
| `src/ioc_enrichment.py` | Intelligence correlation |
| `src/risk_assessor.py` | Heuristic review priority |
| `src/evidence_importer.py` | Evidence preservation |
| `src/report_generator.py` | Unified case reports |
| `src/report_validator.py` | Report validation |
| `src/case_manager.py` | Analyst notes and status |
| `src/case_export.py` | Timeline and analyst exports |
| `dashboard.py` | Local SOC dashboard |
| `pages/` | Additional Streamlit pages |

## Security considerations

- Do not click suspicious URLs or run attachments.
- Avoid rendering phishing HTML in an ordinary web browser.
- Keep raw email evidence and investigation reports private.
- Email authentication results are not independently verified.
- IOC feed matches are investigative leads, not proof of phishing.
- Hostname matches may involve shared infrastructure.
- MITRE ATT&CK mappings are candidates, not confirmed execution.
- Heuristic scores are not calibrated phishing probabilities.
- Analyst names are labels, not authenticated user identities.
- Local case history is not tamper-proof.
- The current system is not designed for concurrent analysts.

## Project limitations

PhishScope v1.0 is an educational, local investigation tool.

Its core functionality has been tested using synthetic email
samples. Validation of detection accuracy against representative,
authorized genuine phishing and legitimate emails is not yet
complete.

The tool does not automatically determine whether an email is
malicious and must not be used as the sole basis for security
enforcement decisions.

## Responsible use

Use PhishScope only on email evidence and infrastructure
you are authorized to investigate.

This project supports defensive analysis and security education.
