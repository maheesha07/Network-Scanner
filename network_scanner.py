"""Tkinter-based TCP network scanner for authorized defensive use.

The application resolves a target host, scans a user-selected TCP port range,
detects likely service names, displays open ports, and exports results as TXT
or CSV reports.
"""

from __future__ import annotations

import csv
import queue
import socket
import threading
import time
import tkinter as tk

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "Network Scanner"
APP_SUBTITLE = "TCP Port Scanner & Service Detection"
SOCKET_TIMEOUT_SECONDS = 0.3
PORT_MIN = 1
PORT_MAX = 65535


COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternative",
    8443: "HTTPS Alternative",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class PortResult:
    """Represents one open TCP port discovered during a scan."""

    port: int
    status: str
    service: str


@dataclass(frozen=True)
class ScanSummary:
    """Summary information collected after a scan completes."""

    target: str
    ip_address: str
    hostname: str
    start_port: int
    end_port: int
    scanned_ports: int
    open_ports: int
    duration_seconds: float


def get_service_name(port: int) -> str:
    """Return a likely TCP service name for a port."""

    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve a hostname or IP address into an IP address and hostname."""

    ip_address = socket.gethostbyname(target)

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        hostname = "Unknown"

    return ip_address, hostname


def is_tcp_port_open(ip_address: str, port: int) -> bool:
    """Return True when a TCP connection to the target port succeeds."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT_SECONDS)
            return sock.connect_ex((ip_address, port)) == 0
    except OSError:
        return False


class NetworkScannerApp:
    """Main Tkinter application for the network scanner."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("920x680")
        self.root.minsize(820, 600)

        self.message_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.open_ports: list[PortResult] = []
        self.scan_summary: ScanSummary | None = None
        self.scan_running = False
        self.scan_thread: threading.Thread | None = None

        self.target_var = tk.StringVar(value="127.0.0.1")
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="500")
        self.status_var = tk.StringVar(value="Ready")
        self.resolved_ip_var = tk.StringVar(value="-")
        self.hostname_var = tk.StringVar(value="-")
        self.scanned_ports_var = tk.StringVar(value="0")
        self.open_ports_var = tk.StringVar(value="0")
        self.duration_var = tk.StringVar(value="0.00s")

        self._configure_styles()
        self._build_interface()
        self._poll_queue()

    def _configure_styles(self) -> None:
        """Apply a clean ttk style while keeping the interface native."""

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.root.configure(background="#f4f6f8")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), background="#f4f6f8")
        style.configure("Subtitle.TLabel", font=("Segoe UI", 11), foreground="#4b5563", background="#f4f6f8")
        style.configure("Panel.TFrame", background="#f4f6f8")
        style.configure("Status.TLabel", foreground="#374151", background="#f4f6f8")
        style.configure("Summary.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_interface(self) -> None:
        """Create and lay out the full GUI."""

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        header = ttk.Frame(self.root, style="Panel.TFrame", padding=(24, 20, 24, 10))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text=APP_SUBTITLE, style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 0))

        form = ttk.LabelFrame(self.root, text="Scan Configuration", padding=(16, 14))
        form.grid(row=1, column=0, sticky="ew", padx=24, pady=(6, 12))
        form.columnconfigure(1, weight=2)
        form.columnconfigure(3, weight=1)
        form.columnconfigure(5, weight=1)

        ttk.Label(form, text="Target IP/Hostname").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(form, textvariable=self.target_var).grid(row=0, column=1, sticky="ew", padx=(0, 16))

        ttk.Label(form, text="Start Port").grid(row=0, column=2, sticky="w", padx=(0, 8))
        ttk.Entry(form, textvariable=self.start_port_var, width=10).grid(row=0, column=3, sticky="ew", padx=(0, 16))

        ttk.Label(form, text="End Port").grid(row=0, column=4, sticky="w", padx=(0, 8))
        ttk.Entry(form, textvariable=self.end_port_var, width=10).grid(row=0, column=5, sticky="ew")

        controls = ttk.Frame(self.root, style="Panel.TFrame", padding=(24, 0, 24, 8))
        controls.grid(row=2, column=0, sticky="ew")
        controls.columnconfigure(4, weight=1)

        self.scan_button = ttk.Button(controls, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 8))

        self.clear_button = ttk.Button(controls, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=1, padx=(0, 8))

        self.export_txt_button = ttk.Button(controls, text="Export TXT", command=self.export_txt)
        self.export_txt_button.grid(row=0, column=2, padx=(0, 8))

        self.export_csv_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_csv_button.grid(row=0, column=3, padx=(0, 8))

        self.progress = ttk.Progressbar(controls, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=5, sticky="ew", pady=(12, 4))

        ttk.Label(controls, textvariable=self.status_var, style="Status.TLabel").grid(
            row=2, column=0, columnspan=5, sticky="w"
        )

        content = ttk.Frame(self.root, style="Panel.TFrame", padding=(24, 0, 24, 12))
        content.grid(row=3, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)

        results_frame = ttk.LabelFrame(content, text="Open Ports", padding=10)
        results_frame.grid(row=0, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.result_table = ttk.Treeview(
            results_frame,
            columns=("port", "status", "service"),
            show="headings",
            selectmode="browse",
        )
        self.result_table.heading("port", text="Port")
        self.result_table.heading("status", text="Status")
        self.result_table.heading("service", text="Service")
        self.result_table.column("port", width=120, minwidth=80, anchor="center", stretch=False)
        self.result_table.column("status", width=140, minwidth=90, anchor="center", stretch=False)
        self.result_table.column("service", width=560, minwidth=220, anchor="w")
        self.result_table.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.result_table.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.result_table.configure(yscrollcommand=scrollbar.set)

        summary = ttk.LabelFrame(self.root, text="Summary", padding=(16, 12))
        summary.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 18))

        for column in range(5):
            summary.columnconfigure(column, weight=1)

        self._add_summary_item(summary, "Resolved IP", self.resolved_ip_var, 0)
        self._add_summary_item(summary, "Hostname", self.hostname_var, 1)
        self._add_summary_item(summary, "Scanned Ports", self.scanned_ports_var, 2)
        self._add_summary_item(summary, "Open Ports", self.open_ports_var, 3)
        self._add_summary_item(summary, "Duration", self.duration_var, 4)

    def _add_summary_item(self, parent: ttk.Frame, label: str, value: tk.StringVar, column: int) -> None:
        """Add one compact label/value pair to the summary section."""

        container = ttk.Frame(parent)
        container.grid(row=0, column=column, sticky="ew", padx=(0, 14))
        ttk.Label(container, text=label).grid(row=0, column=0, sticky="w")
        ttk.Label(container, textvariable=value, style="Summary.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 0))

    def start_scan(self) -> None:
        """Validate user input and start the background scan thread."""

        if self.scan_running:
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Invalid Target", "Please enter a target IP address or hostname.")
            return

        try:
            start_port = int(self.start_port_var.get().strip())
            end_port = int(self.end_port_var.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port Range", "Start port and end port must be valid numbers.")
            return

        validation_error = self._validate_port_range(start_port, end_port)
        if validation_error:
            messagebox.showerror("Invalid Port Range", validation_error)
            return

        self._prepare_scan_ui(start_port, end_port)
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, start_port, end_port),
            daemon=True,
        )
        self.scan_thread.start()

    def _validate_port_range(self, start_port: int, end_port: int) -> str | None:
        """Return a validation error message, or None if the range is valid."""

        if not PORT_MIN <= start_port <= PORT_MAX:
            return f"Start port must be between {PORT_MIN} and {PORT_MAX}."
        if not PORT_MIN <= end_port <= PORT_MAX:
            return f"End port must be between {PORT_MIN} and {PORT_MAX}."
        if start_port > end_port:
            return "Start port cannot be greater than end port."
        return None

    def _prepare_scan_ui(self, start_port: int, end_port: int) -> None:
        """Reset scan state and disable conflicting controls."""

        total_ports = end_port - start_port + 1
        self.scan_running = True
        self.open_ports.clear()
        self.scan_summary = None
        self.result_table.delete(*self.result_table.get_children())
        self.progress.configure(value=0, maximum=total_ports)
        self.status_var.set("Resolving target...")
        self.resolved_ip_var.set("-")
        self.hostname_var.set("-")
        self.scanned_ports_var.set(str(total_ports))
        self.open_ports_var.set("0")
        self.duration_var.set("0.00s")
        self.scan_button.configure(state="disabled")
        self.clear_button.configure(state="disabled")

    def _scan_worker(self, target: str, start_port: int, end_port: int) -> None:
        """Resolve and scan the target without touching Tkinter widgets."""

        started_at = time.perf_counter()

        try:
            ip_address, hostname = resolve_target(target)
        except socket.gaierror:
            self.message_queue.put(("error", "Unable to resolve the target IP address or hostname."))
            return
        except OSError as error:
            self.message_queue.put(("error", f"Target resolution failed: {error}"))
            return

        self.message_queue.put(("resolved", (ip_address, hostname)))

        scanned_ports = 0
        open_ports = 0
        for port in range(start_port, end_port + 1):
            if is_tcp_port_open(ip_address, port):
                open_ports += 1
                result = PortResult(port=port, status="OPEN", service=get_service_name(port))
                self.message_queue.put(("open_port", result))

            scanned_ports += 1
            self.message_queue.put(("progress", (scanned_ports, port, end_port, open_ports)))

        summary = ScanSummary(
            target=target,
            ip_address=ip_address,
            hostname=hostname,
            start_port=start_port,
            end_port=end_port,
            scanned_ports=scanned_ports,
            open_ports=open_ports,
            duration_seconds=time.perf_counter() - started_at,
        )
        self.message_queue.put(("complete", summary))

    def _poll_queue(self) -> None:
        """Process messages sent by the scan thread on the Tkinter thread."""

        while True:
            try:
                message_type, payload = self.message_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "resolved":
                ip_address, hostname = payload
                self.resolved_ip_var.set(ip_address)
                self.hostname_var.set(hostname)
                self.status_var.set(f"Scanning {ip_address}...")
            elif message_type == "open_port":
                self._add_result(payload)
            elif message_type == "progress":
                scanned_ports, current_port, end_port, open_ports = payload
                self._update_progress(scanned_ports, current_port, end_port, open_ports)
            elif message_type == "complete":
                self._finish_scan(payload)
            elif message_type == "error":
                self._handle_scan_error(str(payload))

        self.root.after(50, self._poll_queue)

    def _add_result(self, result: PortResult) -> None:
        """Add one open port to the results table and export list."""

        self.open_ports.append(result)
        self.result_table.insert("", "end", values=(result.port, result.status, result.service))

    def _update_progress(self, scanned_ports: int, current_port: int, end_port: int, open_ports: int) -> None:
        """Refresh scan progress details."""

        self.progress["value"] = scanned_ports
        self.open_ports_var.set(str(open_ports))
        self.status_var.set(f"Scanning port {current_port} of {end_port}")

    def _finish_scan(self, summary: ScanSummary) -> None:
        """Finalize UI state after a successful scan."""

        self.scan_running = False
        self.scan_summary = summary
        self.progress["value"] = summary.scanned_ports
        self.resolved_ip_var.set(summary.ip_address)
        self.hostname_var.set(summary.hostname)
        self.scanned_ports_var.set(str(summary.scanned_ports))
        self.open_ports_var.set(str(summary.open_ports))
        self.duration_var.set(f"{summary.duration_seconds:.2f}s")
        self.status_var.set("Scan completed.")
        self.scan_button.configure(state="normal")
        self.clear_button.configure(state="normal")

        messagebox.showinfo(
            "Scan Complete",
            (
                "Scan completed successfully.\n\n"
                f"Target: {summary.target}\n"
                f"Resolved IP: {summary.ip_address}\n"
                f"Open ports: {summary.open_ports}\n"
                f"Duration: {summary.duration_seconds:.2f} seconds"
            ),
        )

    def _handle_scan_error(self, message: str) -> None:
        """Reset scan controls and show a clean error message."""

        self.scan_running = False
        self.status_var.set("Scan failed.")
        self.scan_button.configure(state="normal")
        self.clear_button.configure(state="normal")
        messagebox.showerror("Scan Error", message)

    def clear_results(self) -> None:
        """Clear scan results and reset summary fields."""

        if self.scan_running:
            messagebox.showwarning("Scan Running", "Please wait until the current scan finishes.")
            return

        self.open_ports.clear()
        self.scan_summary = None
        self.result_table.delete(*self.result_table.get_children())
        self.progress["value"] = 0
        self.status_var.set("Ready")
        self.resolved_ip_var.set("-")
        self.hostname_var.set("-")
        self.scanned_ports_var.set("0")
        self.open_ports_var.set("0")
        self.duration_var.set("0.00s")

    def export_txt(self) -> None:
        """Export the current open-port results as a text report."""

        if not self._has_exportable_results():
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=self._default_report_name("txt"),
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not file_path:
            return

        try:
            self._write_txt_report(Path(file_path))
        except OSError as error:
            messagebox.showerror("Export Error", f"Unable to export TXT report:\n{error}")
            return

        messagebox.showinfo("Export Complete", "TXT report exported successfully.")

    def export_csv(self) -> None:
        """Export the current open-port results as a CSV report."""

        if not self._has_exportable_results():
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=self._default_report_name("csv"),
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if not file_path:
            return

        try:
            self._write_csv_report(Path(file_path))
        except OSError as error:
            messagebox.showerror("Export Error", f"Unable to export CSV report:\n{error}")
            return

        messagebox.showinfo("Export Complete", "CSV report exported successfully.")

    def _has_exportable_results(self) -> bool:
        """Return True if the app has completed results that can be exported."""

        if self.scan_running:
            messagebox.showwarning("Scan Running", "Please wait until the current scan finishes before exporting.")
            return False
        if self.scan_summary is None:
            messagebox.showwarning("No Results", "Run a scan before exporting.")
            return False
        return True

    def _default_report_name(self, extension: str) -> str:
        """Return a timestamped default report filename."""

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return f"network_scan_{timestamp}.{extension}"

    def _write_txt_report(self, file_path: Path) -> None:
        """Write a human-readable scan report."""

        if self.scan_summary is None:
            raise RuntimeError("No scan summary is available.")

        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = self.scan_summary

        with file_path.open("w", encoding="utf-8") as report:
            report.write("=" * 64 + "\n")
            report.write("NETWORK SCANNER REPORT\n")
            report.write("=" * 64 + "\n\n")
            report.write(f"Target        : {summary.target}\n")
            report.write(f"Resolved IP   : {summary.ip_address}\n")
            report.write(f"Hostname      : {summary.hostname}\n")
            report.write(f"Port Range    : {summary.start_port}-{summary.end_port}\n")
            report.write(f"Scanned Ports : {summary.scanned_ports}\n")
            report.write(f"Open Ports    : {summary.open_ports}\n")
            report.write(f"Scan Duration : {summary.duration_seconds:.2f} seconds\n")
            report.write(f"Exported At   : {scanned_at}\n\n")
            report.write(f"{'PORT':<10}{'STATUS':<12}SERVICE\n")
            report.write("-" * 44 + "\n")

            if not self.open_ports:
                report.write("No open TCP ports found.\n")
                return

            for result in self.open_ports:
                report.write(f"{result.port:<10}{result.status:<12}{result.service}\n")

    def _write_csv_report(self, file_path: Path) -> None:
        """Write scan results as CSV data."""

        if self.scan_summary is None:
            raise RuntimeError("No scan summary is available.")

        summary = self.scan_summary

        with file_path.open("w", newline="", encoding="utf-8") as report:
            writer = csv.writer(report)
            writer.writerow(
                [
                    "target",
                    "resolved_ip",
                    "hostname",
                    "start_port",
                    "end_port",
                    "scanned_ports",
                    "open_ports",
                    "duration_seconds",
                    "port",
                    "status",
                    "service",
                ]
            )

            if not self.open_ports:
                writer.writerow(
                    [
                        summary.target,
                        summary.ip_address,
                        summary.hostname,
                        summary.start_port,
                        summary.end_port,
                        summary.scanned_ports,
                        summary.open_ports,
                        f"{summary.duration_seconds:.2f}",
                        "",
                        "",
                        "",
                    ]
                )
                return

            for result in self.open_ports:
                writer.writerow(
                    [
                        summary.target,
                        summary.ip_address,
                        summary.hostname,
                        summary.start_port,
                        summary.end_port,
                        summary.scanned_ports,
                        summary.open_ports,
                        f"{summary.duration_seconds:.2f}",
                        result.port,
                        result.status,
                        result.service,
                    ]
                )


if __name__ == "__main__":
    root_window = tk.Tk()
    app = NetworkScannerApp(root_window)
    root_window.mainloop()
