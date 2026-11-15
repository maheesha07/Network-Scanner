"""Focused regression tests for the CLI conversion of the original scanner."""
import socket
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import network_scanner as scanner


class ScannerTests(unittest.TestCase):
    def test_port_range_validation(self):
        scanner.validate_port_range(1, 65535)
        for start, end in [(0, 80), (1, 65536), (500, 20), (-1, 80)]:
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                scanner.validate_port_range(start, end)

    def test_known_and_unknown_services(self):
        self.assertEqual(scanner.get_service_name(22), "SSH")
        self.assertEqual(scanner.get_service_name(443), "HTTPS")
        with patch.object(scanner.socket, "getservbyport", side_effect=OSError):
            self.assertEqual(scanner.get_service_name(65000), "Unknown")

    def test_no_open_ports_report(self):
        summary = scanner.ScanSummary("localhost", "127.0.0.1", "localhost", 1, 2, 2, 0, 0.03)
        with tempfile.TemporaryDirectory() as folder:
            txt = Path(folder) / "report.txt"
            scanner.write_txt_report(txt, summary, [])
            self.assertIn("No open TCP ports found", txt.read_text(encoding="utf-8"))

    def test_mocked_open_ports_sorted_and_counts(self):
        with patch.object(scanner, "is_tcp_port_open", side_effect=lambda ip, port, timeout: port in (81, 83)):
            summary, results = scanner.scan_ports("localhost", 80, 83, workers=2, resolved=("127.0.0.1", "localhost"))
        self.assertEqual([r.port for r in results], [81, 83])
        self.assertEqual(summary.open_ports, 2)
        self.assertEqual(summary.scanned_ports, 4)

    def test_localhost_listener_and_export(self):
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(10)
        except OSError as error:
            self.skipTest(f"Loopback listener unavailable: {error}")
        with listener:
            port = listener.getsockname()[1]
            summary, results = scanner.scan_ports("127.0.0.1", port, port, workers=1, timeout=1)
            self.assertEqual(summary.scanned_ports, 1)
            self.assertEqual([item.port for item in results], [port])
            with tempfile.TemporaryDirectory() as folder:
                txt = Path(folder) / "scan.txt"
                scanner.write_txt_report(txt, summary, results)
                self.assertIn(str(port), txt.read_text())

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(PROJECT / "network_scanner.py"), *args], text=True, capture_output=True, timeout=20)

    def test_cli_help(self):
        run = self.run_cli("--help")
        self.assertEqual(run.returncode, 0)
        self.assertIn("--export-txt", run.stdout)

    def test_bad_port_ranges(self):
        for args in (("-s", "0"), ("-e", "65536"), ("-s", "10", "-e", "1"), ("-s", "abc")):
            with self.subTest(args=args):
                run = self.run_cli("127.0.0.1", *args)
                self.assertEqual(run.returncode, 2)
                self.assertIn("error:", run.stderr.lower())

    def test_invalid_hostname(self):
        run = self.run_cli("not-a-host.invalid", "--no-progress")
        self.assertEqual(run.returncode, 2)
        self.assertIn("Unable to resolve target", run.stderr)

    def test_no_tkinter_dependency(self):
        source = (PROJECT / "network_scanner.py").read_text(encoding="utf-8")
        self.assertNotIn("import tkinter", source)
        self.assertNotIn("from tkinter", source)


if __name__ == "__main__":
    unittest.main()
