# AI Security Scanner

A command-line tool that scans source code for security vulnerabilities using Google's Gemini API. It flags issues like SQL injection, weak hashing, hardcoded secrets, and command injection, then prints a color-coded severity report.

## Features
- Detects common vulnerability classes (SQLi, command injection, hardcoded credentials, weak crypto, etc.)
- Color-coded severity levels (CRITICAL / HIGH / MEDIUM / LOW)
- Suggests fixes for each finding
- Works on any single Python file

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/security-scanner.git
   cd security-scanner
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Add your API key:
   ```bash
   cp .env.example .env
   # then edit .env and add your GOOGLE_API_KEY
   ```

## Usage

```bash
python scanner.py <path_to_file>
```

Example:
```bash
python scanner.py vulnerable.py
```

## Example Output

The scanner analyzes the target file and prints findings like:

```
SEVERITY: CRITICAL
TYPE: SQL Injection
DESCRIPTION: User input is directly interpolated into the SQL query string.
IMPACT: Attackers can manipulate the query to bypass authentication or exfiltrate data.
FIX: Use parameterized queries instead of string formatting.
```

`vulnerable.py` is included as a sample file containing intentional vulnerabilities for demonstration purposes.

## Tech Stack
- Python
- Google Gemini API (`google-genai`)
- `python-dotenv` for environment config
- `colorama` for terminal colors

## License
MIT