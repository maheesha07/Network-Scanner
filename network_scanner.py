"""Command-line TCP connect port scanner for authorized network assessments."""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Event
from typing import Callable

VERSION = "1.0.0"
SOCKET_TIMEOUT_SECONDS = 0.3
PORT_MIN = 1
PORT_MAX = 65535
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 500
DEFAULT_WORKERS = 32
MAX_WORKERS = 128

# The supplied banner has been restored to its intended 10-line layout.
# These glyphs need UTF-8 terminal support; narrow terminals use a compact title.
BANNER = r"""██▓███   ▒█████   ██▀███  ▄▄▄█████▓     ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███
▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒   ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░   ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░      ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄
▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░    ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░      ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░       ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
░░       ░ ░ ░ ▒    ░░   ░   ░         ░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░
                 ░ ░     ░                       ░  ░ ░            ░  ░         ░          ░    ░  ░   ░
                                                        ░"""

COMMON_SERVICES = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "Microsoft RPC", 137: "NetBIOS Name",
    138: "NetBIOS Datagram", 139: "NetBIOS Session", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "Microsoft SQL Server",
    1521: "Oracle Database", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP Alternative", 8443: "HTTPS Alternative", 27017: "MongoDB",
}


@dataclass(frozen=True)
class PortResult:
    """An open TCP port discovered during a scan."""

    port: int
    status: str
    service: str


@dataclass(frozen=True)
class ScanSummary:
    """Metadata and statistics captured when the scan ends."""

    target: str
    ip_address: str
    hostname: str
    start_port: int
    end_port: int
    scanned_ports: int
    open_ports: int
    duration_seconds: float


def get_service_name(port: int) -> str:
    """Return the conventional service label, not an active fingerprint."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve to IPv4, preserving the original application's behavior."""
    ip_address = socket.gethostbyname(target)
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "Unknown"
    return ip_address, hostname


def is_tcp_port_open(ip_address: str, port: int, timeout: float = SOCKET_TIMEOUT_SECONDS) -> bool:
    """Use the original TCP connect_ex strategy; timeouts count as not open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip_address, port)) == 0
    except OSError:
        return False


def validate_port_range(start_port: int, end_port: int) -> None:
    """Reject invalid TCP ports before making any connections."""
    if not PORT_MIN <= start_port <= PORT_MAX:
        raise ValueError(f"Start port must be between {PORT_MIN} and {PORT_MAX}.")
    if not PORT_MIN <= end_port <= PORT_MAX:
        raise ValueError(f"End port must be between {PORT_MIN} and {PORT_MAX}.")
    if start_port > end_port:
        raise ValueError("Start port cannot be greater than end port.")


def scan_ports(
    target: str,
    start_port: int,
    end_port: int,
    workers: int = DEFAULT_WORKERS,
    timeout: float = SOCKET_TIMEOUT_SECONDS,
    progress: Callable[[int, int, int], None] | None = None,
    resolved: tuple[str, str] | None = None,
) -> tuple[ScanSummary, list[PortResult]]:
    """Run bounded concurrent TCP connect checks; report completed work.

    The executor is intentionally limited to a fixed worker count. Results are
    sorted by port, regardless of the order in which socket calls complete.
    """
    validate_port_range(start_port, end_port)
    if not target.strip():
        raise ValueError("Target IP address or hostname cannot be empty.")
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}.")
    if not 0 < timeout <= 10:
        raise ValueError("Timeout must be greater than 0 and at most 10 seconds.")

    started_at = time.perf_counter()
    ip_address, hostname = resolved if resolved is not None else resolve_target(target)
    results: list[PortResult] = []
    scanned = 0
    interrupted = Event()

    # executor.map can block progress on the slowest port. as_completed yields
    # work in completion order and keeps the terminal progress responsive.
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {}
    try:
        futures = {
            executor.submit(is_tcp_port_open, ip_address, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                results.append(PortResult(port, "OPEN", get_service_name(port)))
            scanned += 1
            if progress is not None:
                progress(scanned, end_port - start_port + 1, len(results))
    except KeyboardInterrupt:
        interrupted.set()
        for future in futures:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=not interrupted.is_set(), cancel_futures=interrupted.is_set())

    results.sort(key=lambda item: item.port)
    summary = ScanSummary(
        target=target,
        ip_address=ip_address,
        hostname=hostname,
        start_port=start_port,
        end_port=end_port,
        scanned_ports=scanned,
        open_ports=len(results),
        duration_seconds=time.perf_counter() - started_at,
    )
    return summary, results


def write_txt_report(file_path: Path, summary: ScanSummary, open_ports: list[PortResult]) -> None:
    """Adapt the original GUI's readable TXT export format."""
    with file_path.open("w", encoding="utf-8") as report:
        report.write("=" * 64 + "\nNETWORK SCANNER REPORT\n" + "=" * 64 + "\n\n")
        report.write(f"Target        : {summary.target}\n")
        report.write(f"Resolved IP   : {summary.ip_address}\n")
        report.write(f"Hostname      : {summary.hostname}\n")
        report.write(f"Port Range    : {summary.start_port}-{summary.end_port}\n")
        report.write("Scan Type     : TCP Connect Scan\n")
        report.write(f"Scanned Ports : {summary.scanned_ports}\n")
        report.write(f"Open Ports    : {summary.open_ports}\n")
        report.write(f"Scan Duration : {summary.duration_seconds:.2f} seconds\n")
        report.write(f"Exported At   : {datetime.now().astimezone().isoformat(timespec='seconds')}\n\n")
        report.write(f"{'PORT':<10}{'STATUS':<12}SERVICE\n")
        report.write("-" * 44 + "\n")
        if not open_ports:
            report.write("No open TCP ports found.\n")
        for result in open_ports:
            report.write(f"{result.port:<10}{result.status:<12}{result.service}\n")


class Terminal:
    """Plain-text output with optional ANSI styling (without dependencies)."""

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def color(self, message: str, color: str) -> str:
        return f"{color}{message}{self.RESET}" if self.enabled else message

    def heading(self, label: str) -> None:
        print("\n" + self.color(f"## {label}", self.CYAN))
        print("-" * 54)


def use_color(no_color: bool) -> bool:
    """Avoid ANSI escape codes for redirected output or NO_COLOR terminals."""
    if no_color or os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Standard Windows terminal supports VT escape sequences with this flag.
        try:
            import ctypes
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except (AttributeError, OSError):
            return False
    return os.environ.get("TERM", "") != "dumb"


def show_banner(term: Terminal) -> None:
    width = shutil.get_terminal_size(fallback=(100, 24)).columns
    if width >= max(len(line) for line in BANNER.splitlines()):
        print(term.color(BANNER, term.CYAN))
    else:
        print(term.color("[ PORT SCANNER ]", term.CYAN))
        print(term.color(f"[INFO] Original ASCII banner needs at least {max(map(len, BANNER.splitlines()))} columns; resize terminal to display it.", term.YELLOW))
    print(term.color("MAHEESHA DASSANAYAKE", term.CYAN))
    print("PYTHON NETWORK PORT SCANNER")
    print(f"VERSION {VERSION}")


def show_results(term: Terminal, summary: ScanSummary, open_ports: list[PortResult]) -> None:
    term.heading("SCAN RESULTS")
    print(f"{'PORT':<11}{'STATE':<13}SERVICE")
    if not open_ports:
        print(term.color("No open TCP ports found in the selected range.", term.YELLOW))
    for result in open_ports:
        print(f"{result.port:<11}{term.color(f'{result.status:<13}', term.GREEN)}{result.service}")
    term.heading("SCAN SUMMARY")
    print(f"Scanned Ports : {summary.scanned_ports}")
    print(f"Open Ports    : {term.color(str(summary.open_ports), term.GREEN)}")
    print(f"Duration      : {summary.duration_seconds:.2f} seconds")
    print(f"Status        : {term.color('Completed', term.GREEN)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_scanner.py",
        usage="%(prog)s TARGET [options]",
        description="Scan an IPv4 host for open TCP ports.",
        formatter_class=argparse.HelpFormatter,
        epilog="Only scan systems you own or are explicitly permitted to test.",
    )
    parser.add_argument("target", metavar="TARGET", help="IPv4 address or resolvable hostname")
    scan_options = parser.add_argument_group("scan options")
    scan_options.add_argument("-s", "--start-port", type=int, default=DEFAULT_START_PORT, metavar="PORT", help=f"first TCP port (default: {DEFAULT_START_PORT})")
    scan_options.add_argument("-e", "--end-port", type=int, default=DEFAULT_END_PORT, metavar="PORT", help=f"last TCP port (default: {DEFAULT_END_PORT})")
    scan_options.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, metavar="N", help=f"concurrent checks, 1-{MAX_WORKERS} (default: {DEFAULT_WORKERS})")
    scan_options.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT_SECONDS, metavar="SECONDS", help=f"per-port timeout, >0 and <=10 (default: {SOCKET_TIMEOUT_SECONDS})")
    output_options = parser.add_argument_group("output options")
    output_options.add_argument("--export-txt", type=Path, metavar="FILE", help="save a readable TXT report")
    output_options.add_argument("--no-color", action="store_true", help="disable terminal colors")
    output_options.add_argument("--no-progress", action="store_true", help="hide progress updates")
    output_options.add_argument("--no-banner", action="store_true", help="hide startup banner")
    parser.add_argument("--version", action="version", version=f"Network Scanner {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = sys.argv[1:] if argv is None else argv
    if ("-h" in arguments or "--help" in arguments) and "--no-banner" not in arguments:
        term = Terminal(use_color("--no-color" in arguments))
        show_banner(term)
        print()
    args = parser.parse_args(arguments)
    try:
        validate_port_range(args.start_port, args.end_port)
        if not 1 <= args.workers <= MAX_WORKERS:
            raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}.")
        if not 0 < args.timeout <= 10:
            raise ValueError("Timeout must be greater than 0 and at most 10 seconds.")
        if not args.target.strip():
            raise ValueError("Target IP address or hostname cannot be empty.")
    except ValueError as error:
        parser.error(str(error))

    term = Terminal(use_color(args.no_color))
    if not args.no_banner:
        show_banner(term)
    print(term.color("\n[INFO] Resolving target...", term.YELLOW))
    try:
        resolved = resolve_target(args.target)
    except (socket.gaierror, socket.herror, OSError) as error:
        print(term.color(f"[ERROR] Unable to resolve target '{args.target}': {error}", term.RED), file=sys.stderr)
        return 2

    term.heading("TARGET INFORMATION")
    print(f"Target       : {args.target}")
    print(f"Resolved IP  : {resolved[0]}")
    print(f"Hostname     : {resolved[1]}")
    print(f"Port Range   : {args.start_port}-{args.end_port}")
    print("Scan Type    : TCP Connect Scan")
    print(f"Workers      : {args.workers}")
    print(f"Timeout      : {args.timeout:g} seconds")

    total = args.end_port - args.start_port + 1
    progress_step = max(1, total // 20)
    progress_enabled = not args.no_progress
    last_progress = 0
    def report_progress(scanned: int, count: int, found: int) -> None:
        nonlocal last_progress
        if progress_enabled and (scanned == count or scanned - last_progress >= progress_step):
            last_progress = scanned
            print(term.color(f"[SCAN] {scanned}/{count} ports checked ({scanned * 100 / count:.0f}%) | {found} open", term.YELLOW), flush=True)

    try:
        print(term.color("\n[INFO] Starting TCP connect scan...", term.YELLOW))
        summary, results = scan_ports(
            args.target, args.start_port, args.end_port,
            workers=args.workers, timeout=args.timeout,
            progress=report_progress, resolved=resolved,
        )
    except KeyboardInterrupt:
        print(term.color("\n[WARN] Scan interrupted; no report was exported.", term.YELLOW), file=sys.stderr)
        return 130
    except OSError as error:
        print(term.color(f"[ERROR] Scan failed: {error}", term.RED), file=sys.stderr)
        return 1
    show_results(term, summary, results)

    if args.export_txt is not None:
        try:
            write_txt_report(args.export_txt, summary, results)
        except OSError as error:
            print(term.color(f"[ERROR] Could not export TXT report to '{args.export_txt}': {error}", term.RED), file=sys.stderr)
            return 1
        print(term.color(f"[OK] TXT report saved: {args.export_txt}", term.GREEN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
