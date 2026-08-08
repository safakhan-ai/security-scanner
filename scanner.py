import os
import sys
import json
import argparse
from dotenv import load_dotenv
import google.genai as genai
from colorama import init, Fore, Style

init(autoreset=True)
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")
client = genai.Client(api_key=api_key)

security_prompt = """
Analyze this code for security vulnerabilities. Be concise.
Return ONLY a valid JSON array (no markdown, no code fences, no explanation text).
Each item must have exactly these fields:
{{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "type": "short vulnerability name",
  "description": "one sentence explaining the issue",
  "impact": "one sentence on potential damage",
  "fix": "code snippet only",
  "line": <line number where the issue starts, integer, or null if unknown>
}}
If there are no issues, return an empty array: []

Code:
{code}
"""

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.YELLOW + Style.BRIGHT,
    "MEDIUM": Fore.BLUE,
    "LOW": Fore.GREEN,
}

SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def parse_findings(response_text):
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"Could not parse AI response as JSON: {e}")
        return []


def print_text_report(findings, file_path):
    if not findings:
        print(f"{Fore.GREEN}No issues found in {file_path}{Style.RESET_ALL}")
        return
    for f in findings:
        color = SEVERITY_COLORS.get(f.get("severity", ""), "")
        print("---")
        print(f"SEVERITY: {color}{f.get('severity')}{Style.RESET_ALL}")
        print(f"TYPE: {f.get('type')}")
        if f.get("line"):
            print(f"LINE: {f.get('line')}")
        print(f"DESCRIPTION: {f.get('description')}")
        print(f"IMPACT: {f.get('impact')}")
        print(f"FIX: {f.get('fix')}")
    print("---")


def build_sarif(findings, file_path):
    results = []
    rules = {}
    for f in findings:
        rule_id = f.get("type", "unknown-vulnerability").lower().replace(" ", "-")
        rules[rule_id] = {
            "id": rule_id,
            "name": f.get("type", "Unknown"),
            "shortDescription": {"text": f.get("type", "Unknown")},
        }
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(f.get("severity"), "warning"),
            "message": {
                "text": f"{f.get('description', '')} Impact: {f.get('impact', '')}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": f.get("line") or 1}
                }
            }]
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GeminiSecurityScanner",
                    "informationUri": "https://github.com/safakhan-ai",
                    "version": "1.0.0",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }


def main():
    parser = argparse.ArgumentParser(description="AI-powered security scanner using Gemini")
    parser.add_argument("file_path", help="Path to the source file to scan")
    parser.add_argument("--format", choices=["text", "sarif"], default="text",
                         help="Output format (default: text)")
    parser.add_argument("--output", help="Output file path (required for sarif format)")
    args = parser.parse_args()

    with open(args.file_path, "r") as f:
        code = f.read()

    prompt = security_prompt.format(code=code)

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash', contents=prompt
        )
        findings = parse_findings(response.text)

        if args.format == "sarif":
            sarif_output = build_sarif(findings, args.file_path)
            out_path = args.output or f"{args.file_path}.sarif.json"
            with open(out_path, "w") as out_f:
                json.dump(sarif_output, out_f, indent=2)
            print(f"{Fore.GREEN}SARIF report written to {out_path}{Style.RESET_ALL}")
        else:
            print_text_report(findings, args.file_path)

    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()