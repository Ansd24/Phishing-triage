# Phishing Triage

A Python command-line tool that checks `.eml` email files for common phishing signs and rates each one 🟢 **Safe**, 🟡 **Suspicious** or 🔴 **Likely Phishing**.

It reads the raw email offline: it never opens links or contacts any server.

## What it checks

| Check | What it looks at | Points |
|---|---|---|
| Authentication header missing | No `Authentication-Results` header | +2 |
| SPF fail | `spf=fail` | +2 |
| DKIM fail | `dkim=fail` | +2 |
| DMARC fail | `dmarc=fail` | +3 |
| Sender mismatch | `Return-Path` address differs from `From` address | +2 |
| Links | Each URL in the plain-text body and each `<a href>` in the HTML body | +1 each |

The total score sets the rating:

| Score | Rating |
|---|---|
| 0–2 | 🟢 Safe |
| 3–5 | 🟡 Suspicious |
| 6+ | 🔴 Likely Phishing |

## Installation

Requires Python 3.10 or newer.

```
git clone <this-repo-url>
cd <repo-folder>
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

## Usage

```
python Triage.py <file-or-folder> [--format {csv,x,t}]
```

- `<file-or-folder>` is a single `.eml` file, or a folder (every `.eml` file in it is checked).
- `--format` sets where the results go:
  - `csv` (default): writes `Report.csv`
  - `x`: writes an Excel file, `Report.xlsx`
  - `t`: prints a table in the terminal

### Examples

```
python Triage.py samples --format t
python Triage.py samples/sample_02.eml
python Triage.py samples --format x
```

Terminal output for the included samples:

```
File Name       Verdict               Score
---------------------------------------------
sample_01.eml   🟢 Safe                2
sample_02.eml   🔴 Likely Phishing     6
sample_03.eml   🔴 Likely Phishing     8
```

The CSV and Excel reports have one row per email with these columns: `file`, `authentication`, `subject`, `sender`, `return_path`, `to`, `urls_found`, `score`, `verdict`.

## Sample emails

The `samples/` folder contains synthetic emails for testing. All addresses and domains in them are made up (`example`, `.test`). No real messages or personal data are included.

## Limitations

- The score is a simple rule-based heuristic, not a final judgement. Use it to prioritise emails for a person to review.
- Every link adds a point, so legitimate newsletters with many links can score higher than expected.
- When given a folder, only files ending in `.eml` are checked.
- Emails with no plain-text part (HTML only) are not supported yet.
- Each run overwrites the previous `Report.csv` / `Report.xlsx`.

## Disclaimer

This project is for learning and defensive use: triaging suspicious emails you are allowed to analyse. Do not upload real emails that contain other people's personal data.
