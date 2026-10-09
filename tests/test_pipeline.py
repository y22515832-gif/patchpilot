import main
from main import scanner_agent, coder_agent, reviewer_agent


def test_detect_and_patch_eval_input():
    code = "value = eval(input())\nprint(value)\n"
    findings = scanner_agent(code)

    assert any(f["id"] == "PY-EVAL-001" for f in findings)

    patched, actions = coder_agent(code, findings)

    assert "eval(input())" not in patched.replace(
        "ast.literal_eval(input())", ""
    )
    assert "safe_calculate(input())" in patched
    assert "eval(input())" not in patched
    assert main. tester_agent(patched)["passed"] is True
    assert reviewer_agent(code, patched, findings)["passed"] is True


def test_clean_code_has_no_findings():
    code = "value = input()\nprint(value)\n"
    assert scanner_agent(code) == []


def test_exec_is_detected_but_not_automatically_changed():
    code = "exec(input())\n"
    findings = scanner_agent(code)

    assert any(f["id"] == "PY-EXEC-001" for f in findings)

    patched, _ = coder_agent(code, findings)
    assert patched == code


def test_syntax_error_fails_validation():
    result =main. tester_agent("def broken(:\n pass")
    assert result["passed"] is False
