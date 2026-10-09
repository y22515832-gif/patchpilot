from pathlib import Path
import ast
import re
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent
app = FastAPI(title="Autonomous Vulnerability Patching Pipeline", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class PipelineRequest(BaseModel):
    code: str = Field(min_length=1, max_length=100_000)


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

  - id: python-unsafe-pickle
    languages: [python]
    severity: ERROR
    message: Avoid pickle.loads() on untrusted data.
    pattern: pickle.loads(...)

  - id: python-unsafe-yaml-load
    languages: [python]
    severity: WARNING
    message: Review yaml.load() and use a safe loader for untrusted data.
    pattern: yaml.load(...)

  - id: python-subprocess-shell
    languages: [python]
    severity: WARNING
    message: Review subprocess calls using shell=True for command injection.
    pattern: subprocess.run(..., shell=True, ...)
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
             "id": (
    "PY-EVAL-001" if "eval" in item.get("check_id", "").lower()
    else "PY-EXEC-001" if "exec" in item.get("check_id", "").lower()
    else item.get("check_id", "SEMGREP-FINDING").split(".")[-1]
),
            "severity": extra.get("severity", "WARNING").title(),
            "title": extra.get("message", "Security finding"),
            "description": extra.get("message", "Semgrep reported a potential issue."),
            "line": start_line,
            "snippet": snippet,
        })

    return findings


def coder_agent(code: str, findings: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Apply only a known, narrow transformation."""
    patched = code
    actions = []

    if any(f["id"] == "PY-EVAL-001" for f in findings):
        pattern = r"\beval\s*\(\s*input\s*\(\s*\)\s*\)"
        new_code, count = re.subn(
            pattern,
            "safe_calculate(input())",
            patched,
        )
        if count:
            patched = new_code
            actions.append(
                "Replaced eval(input()) with safe_calculate(input())."
            )
        else:
            actions.append(
                "Unsupported eval() usage: automatic patch skipped; manual review required."
            )

    if any(f["id"] == "PY-EXEC-001" for f in findings):
        actions.append(
            "No automatic patch generated for exec(); manual review required."
        )

    if not actions:
        actions.append("No supported automatic patch was required.")

    return patched, actions

def reviewer_agent(original: str, patched: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform rule-based checks; human review is still required."""
    checks = []

    if any(f["id"] == "PY-EVAL-001" for f in findings):
        remains = re.search(r"\beval\s*\(", patched)
        checks.append({
            "name": "Remove unsafe eval()",
            "passed": remains is None,
        })

    if any(f["id"] == "PY-EXEC-001" for f in findings):
        remains = re.search(r"\bexec\s*\(", patched)
        checks.append({
            "name": "Remove unsafe exec()",
            "passed": remains is None,
        })

    checks.append({
        "name": "Patch changes source",
        "passed": (patched != original) if findings else (patched == original),
    })

    return {
        "checks": checks,
        "passed": all(item["passed"] for item in checks),
        "note": "Rule-based review only; a human must review the final change.",
    }

def tester_agent(code: str) -> dict[str, Any]:
    """Validate syntax without executing submitted code."""
    checks = []

    try:
        ast.parse(code)
        checks.append({
            "name": "Python syntax",
            "passed": True
        })
    except SyntaxError as exc:
        checks.append({
            "name": "Python syntax",
            "passed": False,
            "detail": (
                f"Line {exc.lineno}: {exc.msg}"
            )
        })

    return {
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
        "message": (
            "Syntax validation passed; code was not executed."
            if all(item["passed"] for item in checks)
            else "Syntax validation failed. Reject this patch."
        )
    }



@app.get("/")
def home():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "app": app.title, "version": app.version}


@app.post("/api/pipeline")
def run_pipeline(request: PipelineRequest):
    code = request.code
    findings = scanner_agent(code)
    patched, actions = coder_agent(code, findings)
    review = reviewer_agent(code, patched, findings)
    tests = tester_agent(patched)




    if not review["passed"] or not tests["passed"]:
        patched = code
        actions.append("Patch rejected because validation failed.")




    return {
        "summary": {
            "findings": len(findings),
            "patch_changed_code": patched != code,
            "review_passed": review["passed"],
            "tests_passed": tests["passed"],
            "automatic_patch_available": patched != code,
        },
        "agents": [
            {"name": "Scanner Agent", "status": "completed", "detail": f"{len(findings)} finding(s)"},
            {"name": "Coder Agent", "status": "completed", "detail": "; ".join(actions)},
            {"name": "Reviewer Agent", "status": "passed" if review["passed"] else "needs review", "detail": review["note"]},
            {"name": "Tester Agent", "status": "passed" if tests["passed"] else "failed", "detail": tests["message"]},
        ],
        "findings": findings,
        "patch_actions": actions,
        "original_code": code,
        "patched_code": patched,
        "review": review,
        "tests": tests,
        "disclaimer": "Educational MVP: the scanner covers only two illustrative patterns and does not replace a production SAST tool.",
    }
