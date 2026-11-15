# Python Network Port Scanner

**Author:** Maheesha Dassanayake  
**Version:** 1.0.0  
**GitHub:** [maheesha07](https://github.com/maheesha07)

A lightweight, terminal-only **IPv4 TCP connect port scanner** for learning Python networking and performing authorized system assessments. It provides socket-based scanning, hostname resolution, conventional port-to-service lookup, scan summaries, and readable TXT reports.

> **Authorization required:** Only scan computers or networks you own or have explicit permission to test.

## Features

- IPv4/hostname resolution with reverse-hostname lookup when available
- Configurable inclusive TCP port range (`1`–`65535`)
- TCP connect scanning using Python `socket.connect_ex` (no raw sockets or privileged access required)
- Bounded thread pool (default: 32, maximum: 128 workers) with configurable per-port timeout
- Terminal progress, sorted open-port table, scan duration, and summary
- Original common TCP service-name mapping, plus OS service database fallback
- Optional readable TXT reports, including scans with no open ports
- Optional ANSI colors, automatic plain-text fallback, and `--no-color`
- Input validation, useful nonzero exit codes, Ctrl+C handling
- No GUI, Tkinter, Colorama, or third-party Python dependencies

**Limitations:** This is not Nmap. Service names are inferred from conventional port assignments, **not** verified by probing a service or reading banners. Closed, filtered, unreachable, and timed-out connections are all reported only as *not open*; they are not distinguished. This tool scans **IPv4 only** and does not implement SYN, UDP, stealth, exploitation, or evasion methods.

## Requirements / technologies

- Python **3.10 or newer**
- Standard library: `argparse`, `socket`, `concurrent.futures`, `threading`, `pathlib`, `time`, `dataclasses`, `datetime`
- Windows Terminal/PowerShell or a UTF-8-capable Linux terminal recommended for the decorative ASCII banner

`requirements.txt` intentionally contains no packages to install.

## Installation

### Kali Linux / Debian-based Linux

```bash
git clone https://github.com/maheesha07/Network-Scanner.git
cd Network-Scanner
python3 --version
python3 network_scanner.py --help
```

Alternatively extract this ZIP and `cd Network-Scanner`. No `sudo`, virtual environment, or `pip install` is needed to run the scanner.

### Windows (PowerShell)

Install Python 3.10+ from [python.org](https://www.python.org/downloads/) if needed, enabling **Add Python to PATH**.

```powershell
git clone https://github.com/maheesha07/Network-Scanner.git
cd Network-Scanner
py -3 --version
py -3 network_scanner.py --help
```

Or unzip the downloaded project, open PowerShell in the `Network-Scanner` directory, and run the same Python command. If `py` is unavailable, use `python` instead.

The ASCII banner fits terminals at least **69 columns** wide. Narrower terminals show a compact title. The application remains functional without the full banner or colors.

## CLI usage

```text
network_scanner.py TARGET [options]
```

| Option | Description | Default |
| --- | --- | --- |
| `TARGET` | IPv4 address or hostname (required) | — |
| `-s`, `--start-port` | First TCP port | `1` |
| `-e`, `--end-port` | Last TCP port | `500` |
| `-w`, `--workers` | Number of concurrent connections (`1`–`128`) | `32` |
| `--timeout` | Per-port socket timeout (`>0`, up to `10` seconds) | `0.3` |
| `--export-txt FILE` | Save a readable TXT report | — |
| `--no-color` | Disable terminal colors | Automatic detection |
| `--no-progress` | Suppress progress messages | Show progress |
| `--no-banner` | Hide decorative startup banner | Show banner |
| `--version` | Print the version | — |
| `-h`, `--help` | Show command help | — |

Port endpoints are inclusive; `-s 20 -e 100` checks **81 ports**. Hostnames resolve to one IPv4 address. Concurrency is limited to avoid creating excessive simultaneous network connections.

## Command examples

```bash
# Show built-in help
python3 network_scanner.py --help

# Scan the first 1,000 ports on your own computer
python3 network_scanner.py 127.0.0.1 -s 1 -e 1000

# Check a custom range on localhost
python3 network_scanner.py 127.0.0.1 -s 20 -e 100

# Save a TXT report; create reports/ first if needed
mkdir -p reports
python3 network_scanner.py 127.0.0.1 -s 1 -e 1000 \
  --export-txt reports/scan.txt

# Use fewer workers / longer timeout and hide progress
python3 network_scanner.py 127.0.0.1 -s 1 -e 100 -w 8 --timeout 1 --no-progress
```

**Windows PowerShell:** Use `py -3` in place of `python3`; commands can be written on a single line. Create the reports folder using `New-Item -ItemType Directory -Force reports`.

## Example terminal output

This **illustrative example** shows a single TCP listener on `127.0.0.1:8000`; results will differ on your device. The decorative startup banner and some progress lines are omitted for brevity.

```text
MAHEESHA DASSANAYAKE
PYTHON NETWORK PORT SCANNER
VERSION 1.0.0

## TARGET INFORMATION
------------------------------------------------------
Target       : 127.0.0.1
Resolved IP  : 127.0.0.1
Hostname     : localhost
Port Range   : 7999-8001
Scan Type    : TCP Connect Scan
Workers      : 32
Timeout      : 0.3 seconds

[INFO] Starting TCP connect scan...
[SCAN] 3/3 ports checked (100%) | 1 open

## SCAN RESULTS
------------------------------------------------------
PORT       STATE        SERVICE
8000       OPEN         Unknown

## SCAN SUMMARY
------------------------------------------------------
Scanned Ports : 3
Open Ports    : 1
Duration      : 0.02 seconds
Status        : Completed
```

The application never hardcodes discovered ports. A port's service label reflects the local service database and port mapping, not the process actually listening there.

## Report exporting

Use `--export-txt` to choose a report filename. Parent directories must already exist; exporting to an unwritable or missing directory produces a clear error message. Reports are plain UTF-8 text without terminal color sequences. A successful scan with no open ports still creates a valid report.

```bash
python3 network_scanner.py localhost -s 1 -e 100 --export-txt reports/local.txt
```

- **TXT** includes target, resolved IP, reverse hostname, scanned range, duration, timestamp, and the discovered ports table.

### Scan state and clearing results

Each invocation starts fresh, so no previous results persist in memory. There is no need for a GUI-style **Clear Results** button. Rerun the command to scan again. Existing report files are overwritten only when you explicitly reuse their paths.

### Exit codes

- `0`: Scan complete (including no open ports), requested exports saved.
- `1`: Scan/export error.
- `2`: Invalid CLI input or hostname resolution error.
- `130`: Interrupted with Ctrl+C; no reports exported.

## Project structure

```text
Network-Scanner/
├── network_scanner.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── reports/
│   └── .gitkeep
├── screenshots/
│   ├── .gitkeep
│   └── terminal-output-example.txt
└── tests/
    └── test_network_scanner.py
```

`reports/` is intended for local generated reports, which Git ignores. `screenshots/` is reserved for future genuine terminal screenshots (no mock image is shipped). The included tests cover port-range validation, expected socket behavior, report output, and subprocess CLI errors.

## Running tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile network_scanner.py
python3 network_scanner.py --help
```

Local loopback tests use a temporary listening socket and do not contact external hosts. Tests that require socket availability may be skipped in restricted execution environments.

## Ethical use

This tool is intended exclusively for defensive learning, troubleshooting, and authorized network assessments. Scan **only systems you own or have explicit permission to test**. Do not use it for unauthorized reconnaissance or intrusive activity. The scanner offers no stealth, credential attacks, exploitation, or bypass functionality.

## Author and license

Developed by **Maheesha Dassanayake** — [GitHub profile](https://github.com/maheesha07).  
License: [MIT](LICENSE). Originally developed as a Tkinter GUI app; refactored into a terminal-only Python CLI.
