# Network Scanner

GitHub author: maheesha07

## Project Overview

Network Scanner is an educational cybersecurity and networking project built with Python. It provides a graphical TCP port scanner for checking systems and networks that you own or have explicit permission to test.

A Python-based TCP network scanner with a graphical interface, port scanning, service detection, progress tracking, and TXT/CSV report export.

## Features

- Tkinter/ttk graphical user interface
- Target hostname and IP address resolution
- Configurable TCP start and end port range
- Service detection for common TCP ports
- Responsive scanning with background threading
- Progress bar and current scan status
- Results table showing port, status, and service
- Summary section with resolved IP, hostname, scanned ports, open ports, and duration
- TXT report export
- CSV report export
- Input validation and clear error messages
- Clear Results button

## Screenshot

![Network Scanner](screenshots/network-scanner.png)

## Technologies Used

- Python
- socket
- Tkinter / ttk
- threading
- csv
- datetime

## Installation

1. Clone the repository:

```bash
git clone https://github.com/maheesha07/Network-Scanner.git
```

2. Open the project folder:

```bash
cd Network-Scanner
```

3. Use Python 3.10 or newer. No external Python packages are required.

## How to Run

```bash
python network_scanner.py
```

On some systems, you may need to use:

```bash
python3 network_scanner.py
```

## How to Use

1. Enter a target IP address or hostname.
2. Enter the start port and end port.
3. Click **Start Scan**.
4. Review open TCP ports in the results table.
5. Use **Export TXT** or **Export CSV** to save a report.
6. Use **Clear Results** to reset the interface.

## Example Scan

For a safe local test, scan your own computer:

- Target IP/Hostname: `127.0.0.1`
- Start Port: `1`
- End Port: `500`

The scanner will resolve the target, check each TCP port in the selected range, display any open ports, and show the scan duration.

## Project Structure

```text
Network-Scanner/
|-- network_scanner.py
|-- README.md
|-- requirements.txt
|-- .gitignore
|-- LICENSE
`-- screenshots/
    `-- .gitkeep
```

## Exported Reports

TXT reports provide a readable summary of the scan and a list of discovered open TCP ports.

CSV reports provide structured scan data that can be opened in spreadsheet tools or used for later analysis.

Generated report files are ignored by Git when they match these patterns:

- `network_scan_*.txt`
- `network_scan_*.csv`
- `scan_results_*.txt`
- `scan_results_*.csv`

## Security / Ethical Use Disclaimer

This project is intended only for defensive, educational, and authorized network testing. Only scan networks, hosts, and devices that you own or have explicit permission to assess.

Do not use this tool for unauthorized scanning, intrusion attempts, exploitation, credential attacks, stealth scanning, evasion, or any activity intended to harm systems or bypass security controls.

## Future Improvements

- Add optional scan profiles for common port ranges
- Add export metadata such as operating system and scanner version
- Add a cancel scan button
- Add optional dark mode
- Add automated tests for validation and report formatting

## Author

maheesha07
