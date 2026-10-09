# PatchPilot — Autonomous Multi-Agent Vulnerability Patching Pipeline

A local educational MVP for demonstrating a multi-agent security remediation workflow.

## What it does

- Scanner Agent: detects two illustrative Python patterns: `eval(input())` and `exec(input())`.
- Coder Agent: automatically patches the known `eval(input())` pattern using `ast.literal_eval`.
- Reviewer Agent: checks a few explicit patch conditions.
- Tester Agent: parses the resulting Python source to validate syntax.
- Browser dashboard: shows findings, agent status, patch output and checks.

## Important limitations

This is a demo, not a production security scanner. It does not scan dependency CVEs, clone arbitrary repositories, execute submitted code, isolate builds in a container, use an LLM, or create GitHub pull requests. The Tester Agent deliberately does not execute source code. Only use the sample or code you are authorized to review.

`ast.literal_eval` is safer than `eval` for Python literals, but it only accepts literal structures and is not a drop-in replacement for every use of `eval`. Validate the intended input format and handle errors in real applications.

## Install on Kali Linux / Ubuntu

Python 3.10+ is recommended.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd autonomous-patching-pipeline
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If your terminal says `externally-managed-environment`, keep using the virtual environment above; do not force-install packages into system Python.

## Run the app

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Open this URL in your browser:

http://127.0.0.1:8000

Stop the server with `Ctrl+C`.

## Run automated tests

In another terminal, from the project folder:

```bash
source .venv/bin/activate
pytest -q
```

Expected: 4 tests pass.

## Demo steps

1. Open the dashboard.
2. Keep the default sample `user_value = eval(input())`.
3. Click **Run pipeline**.
4. Show the finding, generated patch, reviewer checks and syntax test.
5. Replace the sample with `print("hello")`, run again, and show zero findings.
6. Try `exec(input())` to show that the pipeline detects it but intentionally asks for manual review rather than applying an unsupported patch.

## Suggested next milestones

1. Add Semgrep rules and dependency scanning (for example, OSV-Scanner).
2. Add repository upload with strict archive path/size checks.
3. Run project tests only inside a disposable, network-disabled container with resource limits; never execute untrusted code directly on the host.
4. Add an LLM coder with structured outputs, patch-size limits, and a separate reviewer.
5. Add GitHub App authentication with least-privilege permissions and open a draft pull request only after tests and review pass.
6. Store audit logs and require human approval before merging.

Container isolation reduces risk but is not a guarantee; use least privilege and avoid mounting host secrets into test containers.
