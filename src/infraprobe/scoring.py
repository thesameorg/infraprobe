from infraprobe.models import Finding, Severity, SeveritySummary

_SEVERITY_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: -40,
    Severity.HIGH: -20,
    Severity.MEDIUM: -10,
    Severity.LOW: -3,
    Severity.INFO: 0,
}

_GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (100, "A+"),
    (90, "A"),
    (85, "B+"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def calculate_score(findings: list[Finding]) -> tuple[str, SeveritySummary]:
    summary = SeveritySummary()
    points = 100

    for f in findings:
        match f.severity:
            case Severity.CRITICAL:
                summary.critical += 1
            case Severity.HIGH:
                summary.high += 1
            case Severity.MEDIUM:
                summary.medium += 1
            case Severity.LOW:
                summary.low += 1
            case Severity.INFO:
                summary.info += 1
        points += _SEVERITY_POINTS[f.severity]

    points = max(0, min(100, points))

    grade = "F"
    for threshold, letter in _GRADE_THRESHOLDS:
        if points >= threshold:
            grade = letter
            break

    return grade, summary
