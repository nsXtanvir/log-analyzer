"""Log Analyzer: a small command-line tool for spotting problems in server logs.

Features
--------
* Load one or many CSV log files (columns: timestamp, server, severity, message)
* Filter by minimum severity and sort most severe first
* Extract structured error codes such as ERR-DISK-01 with regular expressions
* Count events by severity
* Flag possible brute-force attacks (many failed logins from one IP address)
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

SEVERITY_LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

ERROR_CODE_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2,4}-[A-Z]{2,4}-\d{2}(?!\d)")
FAILED_LOGIN_RE = re.compile(
    r"failed login.*?\bfrom\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", re.IGNORECASE
)
REQUIRED_COLUMNS = {"timestamp", "server", "severity", "message"}


def load_logs(file_paths):
    """Load CSV log files into one DataFrame.

    Raises FileNotFoundError for a missing file and ValueError if a file
    is missing required columns or contains unknown severity values.
    """
    frames = []
    for path in file_paths:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        df = pd.read_csv(path)
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            raise ValueError(f"{path} is missing columns: {sorted(missing)}")
        unknown = set(df["severity"]) - set(SEVERITY_LEVELS)
        if unknown:
            raise ValueError(f"{path} has unknown severity values: {sorted(unknown)}")
        frames.append(df)
    if not frames:
        raise ValueError("No log files given")
    return pd.concat(frames, ignore_index=True)


def filter_and_sort(df, min_severity="INFO"):
    """Keep events at or above min_severity; most severe first, then oldest first."""
    if min_severity not in SEVERITY_LEVELS:
        raise ValueError(f"Unknown severity: {min_severity}")
    out = df.copy()
    out["level"] = out["severity"].map(SEVERITY_LEVELS)
    out = out[out["level"] >= SEVERITY_LEVELS[min_severity]]
    out = out.sort_values(["level", "timestamp"], ascending=[False, True])
    return out.drop(columns="level").reset_index(drop=True)


def count_by_severity(df):
    """Return a Counter of events per severity level."""
    return Counter(df["severity"])


def extract_error_codes(messages):
    """Return the error code found in each message (at most one per message)."""
    codes = []
    for message in messages:
        match = ERROR_CODE_RE.search(str(message))
        if match:
            codes.append(match.group(0))
    return codes


def detect_bruteforce(df, threshold=3):
    """Find IPs with at least `threshold` failed-login messages.

    Returns a dict {ip: attempts}, sorted from most to fewest attempts.
    """
    attempts = Counter()
    for message in df["message"]:
        match = FAILED_LOGIN_RE.search(str(message))
        if match:
            attempts[match.group("ip")] += 1
    suspicious = {ip: n for ip, n in attempts.items() if n >= threshold}
    return dict(sorted(suspicious.items(), key=lambda item: -item[1]))


def build_report(df, threshold=3):
    """Collect everything into one dictionary."""
    return {
        "total_events": int(len(df)),
        "severity_counts": dict(count_by_severity(df)),
        "error_codes": dict(Counter(extract_error_codes(df["message"]))),
        "suspicious_ips": detect_bruteforce(df, threshold),
    }


def format_report(report):
    """Turn a report dictionary into readable text."""
    lines = ["=== Log Analyzer Report ===", f"Total events: {report['total_events']}", ""]
    lines.append("Events by severity:")
    for level in sorted(SEVERITY_LEVELS, key=SEVERITY_LEVELS.get, reverse=True):
        if level in report["severity_counts"]:
            lines.append(f"  {level:<9} {report['severity_counts'][level]}")
    lines.append("")
    lines.append("Error codes:")
    if report["error_codes"]:
        for code, n in sorted(report["error_codes"].items(), key=lambda i: (-i[1], i[0])):
            lines.append(f"  {code:<14} x{n}")
    else:
        lines.append("  none found")
    lines.append("")
    lines.append("Possible brute-force sources:")
    if report["suspicious_ips"]:
        for ip, n in report["suspicious_ips"].items():
            lines.append(f"  {ip:<16} {n} failed logins")
    else:
        lines.append("  none detected")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze server log CSV files.")
    parser.add_argument("files", nargs="+", help="one or more CSV log files")
    parser.add_argument("--min-severity", default="INFO", choices=list(SEVERITY_LEVELS))
    parser.add_argument("--threshold", type=int, default=3,
                        help="failed logins from one IP before it is flagged (default 3)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    try:
        df = filter_and_sort(load_logs(args.files), args.min_severity)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    report = build_report(df, args.threshold)
    print(json.dumps(report, indent=2) if args.json else format_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
