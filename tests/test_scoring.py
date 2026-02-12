from infraprobe.models import Finding, Severity
from infraprobe.scoring import calculate_score


def test_perfect_score():
    findings = [Finding(severity=Severity.INFO, title="ok", description="fine")]
    grade, summary = calculate_score(findings)
    assert grade == "A+"
    assert summary.info == 1
    assert summary.critical == 0


def test_one_critical_drops_to_d():
    findings = [Finding(severity=Severity.CRITICAL, title="bad", description="very bad")]
    grade, summary = calculate_score(findings)
    assert grade == "D"
    assert summary.critical == 1


def test_multiple_mediums():
    findings = [Finding(severity=Severity.MEDIUM, title=f"m{i}", description="med") for i in range(3)]
    grade, summary = calculate_score(findings)
    assert grade == "C"
    assert summary.medium == 3


def test_floor_at_zero():
    findings = [Finding(severity=Severity.CRITICAL, title=f"c{i}", description="crit") for i in range(5)]
    grade, summary = calculate_score(findings)
    assert grade == "F"
    assert summary.critical == 5


def test_empty_findings():
    grade, summary = calculate_score([])
    assert grade == "A+"
