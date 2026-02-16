"""Convert InfraProbe scan results to CSV format.

One row per finding. Checks with errors and no findings produce a single
error row. Checks with no findings and no error are omitted.
"""

import csv
import io
import json

from infraprobe.models import ScanResponse, TargetResult

_COLUMNS = ["target", "check", "severity", "title", "description", "details", "score"]


def scan_response_to_csv(response: ScanResponse) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_COLUMNS)
    for target_result in response.results:
        _write_target(writer, target_result)
    return buf.getvalue()


def target_result_to_csv(result: TargetResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_COLUMNS)
    _write_target(writer, result)
    return buf.getvalue()


def _write_target(writer: csv.writer, target_result: TargetResult) -> None:
    target = target_result.target
    score = target_result.score

    for check_name, check_result in target_result.results.items():
        if check_result.findings:
            for finding in check_result.findings:
                writer.writerow(
                    [
                        target,
                        check_name,
                        finding.severity,
                        finding.title,
                        finding.description,
                        json.dumps(finding.details) if finding.details else "",
                        score,
                    ]
                )
        elif check_result.error:
            writer.writerow(
                [
                    target,
                    check_name,
                    "error",
                    "Scanner error",
                    check_result.error,
                    "",
                    score,
                ]
            )
