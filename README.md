# Log Analyzer

A small Python command-line tool that reads server log files, ranks events by severity, extracts error codes, and flags possible **brute-force login attacks**.

Built to practice Python, pandas, regular expressions, error handling, and basic security thinking.

## Features
- Load one or many CSV log files at once
- Filter by minimum severity and sort most severe first
- Extract structured error codes (e.g. `ERR-DISK-02`) with regex
- Count events by severity
- Flag IP addresses with repeated failed logins
- Text or JSON output, clear errors for missing files and bad data

## Install
```bash
git clone https://github.com/nsXtanvir/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

## Usage
```bash
python log_analyzer.py sample_data/web_server.csv sample_data/db_server.csv
python log_analyzer.py sample_data/*.csv --min-severity WARNING
python log_analyzer.py sample_data/*.csv --threshold 2 --json
```

### Options
| Option | Description |
|---|---|
| `--min-severity` | `DEBUG`, `INFO` (default), `WARNING`, `ERROR`, `CRITICAL` |
| `--threshold` | Failed logins from one IP before it is flagged (default 3) |
| `--json` | Print the report as JSON |

### Example output
```
=== Log Analyzer Report ===
Total events: 11

Events by severity:
  CRITICAL  1
  ERROR     3
  WARNING   7

Error codes:
  ERR-DB-01      x2
  ERR-DISK-02    x1
  ERR-QRY-03     x1
  WARN-MEM-01    x1

Possible brute-force sources:
  203.0.113.45     4 failed logins
```

## Log format
CSV with these columns: `timestamp, server, severity, message`

```csv
timestamp,server,severity,message
2026-01-10 09:12:03,web-01,WARNING,Failed login for admin from 203.0.113.45
```

## Security notes
- Sample data uses reserved documentation IP ranges and fake events only.
- No secrets, tokens or credentials belong in this repository.

## Ideas for next steps
- Parse real `auth.log` / syslog formats
- Time-window detection (e.g. 5 failed logins within 1 minute)
- Export reports to CSV or HTML

## Author
Najmos Sakib Tanvir
