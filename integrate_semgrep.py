from pathlib import Path

path = Path("main.py")
source = path.read_text()

start = source.index("def scanner_agent(")
end = source.index("\ndef coder_agent(", start)

replacement = r'''
def scanner_agent(code: str) -> list[dict[str, Any]]:
    """Scan Python source using Semgrep and return dashboard-compatible findings."""
    import json
    import subprocess
    import tempfile

    rule = """
rules:
  - id: python-unsafe-eval
    languages: [python]
    severity: ERROR
    message: Avoid eval() on untrusted input.
    pattern: eval(...)
  - id: python-unsafe-exec
    languages: [python]
    severity: ERROR
    message: Avoid exec() on untrusted input.
    pattern: exec(...)
"""

    with tempfile.TemporaryDirectory(prefix="patchpilot-") as temp:
        temp_path = Path(temp)
        target = temp_path / "submitted.py"
        config = temp_path / "rules.yml"
        target.write_text(code)
        config.write_text(rule)

        try:
            result = subprocess.run(
                [
                    "semgrep", "scan",
                    "--json",
                    "--config", str(config),
                    "--no-git-ignore",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            report = json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return [{
                "id": "SEMGREP-ERROR",
                "severity": "Medium",
                "title": "Security scan could not complete",
                "description": "Semgrep failed or timed out. Review scanner setup before accepting this code.",
                "line": 1,
                "snippet": code.splitlines()[0][:240] if code.splitlines() else "",
            }]

    findings = []
    for item in report.get("results", []):
        extra = item.get("extra", {})
        start_line = item.get("start", {}).get("line", 1)
        lines = code.splitlines()
        snippet = lines[start_line - 1].strip()[:240] if 1 <= start_line <= len(lines) else ""

        findings.append({
            "id": item.get("check_id", "SEMGREP-FINDING").split(".")[-1],
            "severity": extra.get("severity", "WARNING").title(),
            "title": extra.get("message", "Security finding"),
            "description": extra.get("message", "Semgrep reported a potential issue."),
            "line": start_line,
            "snippet": snippet,
        })

    return findings
'''

path.write_text(source[:start] + replacement.lstrip() + source[end:])
print("Semgrep scanner integrated into main.py")
