import csv
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import inventory as inv


class InventoryTests(unittest.TestCase):
    def test_targets_and_ports(self):
        self.assertEqual(inv.targets("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(inv.targets("192.0.2.0/30"), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(inv.ports("443,80,443"), [80, 443])
        for value in ("0", "65536", "abc", ""):
            with self.assertRaises(ValueError):
                inv.ports(value)
        with self.assertRaises(ValueError):
            inv.targets("10.0.0.0/8")

    def test_real_loopback_open_port(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            row = inv.scan_host("127.0.0.1", [port])
            self.assertEqual(row["open_ports"], str(port))
            self.assertEqual(row["status"], "responding")

    def test_refusal_timeout_permission(self):
        for error, expected in [(ConnectionRefusedError(), "responding"),
                                (TimeoutError(), "no_response"),
                                (PermissionError("denied"), "no_response")]:
            with patch("inventory.socket.socket") as factory:
                factory.return_value.__enter__.return_value.connect.side_effect = error
                row = inv.scan_host("127.0.0.1", [80])
                self.assertEqual(row["status"], expected)
                self.assertEqual(row["open_ports"], "")
                if isinstance(error, PermissionError):
                    self.assertIn("denied", row["errors"])

    def test_ping_failures(self):
        for error, expected in [(FileNotFoundError(), "unavailable"),
                                (subprocess.TimeoutExpired("ping", 1), "timeout"),
                                (PermissionError(), "error")]:
            with patch("inventory.subprocess.run", side_effect=error):
                self.assertEqual(inv.ping_host("127.0.0.1", 1)[0], expected)

    def test_comparison(self):
        base = {"127.0.0.1": {"status": "responding", "open_ports": "80"}}
        for state, opened, expected in [("responding", "80", "unchanged"),
                                         ("responding", "443", "ports_changed"),
                                         ("no_response", "", "response_changed")]:
            row = dict(ip="127.0.0.1", status=state, open_ports=opened)
            self.assertEqual(inv.compare([row], base)[0]["change"], expected)
        self.assertEqual(inv.compare([dict(ip="127.0.0.2")], base)[0]["change"], "new_address")

    def test_csv_roundtrip_and_duplicate_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.csv"
            row = dict(ip="127.0.0.1", status="responding", open_ports="443;80", errors="=unsafe")
            inv.write_report(path, [row])
            self.assertEqual(inv.read_baseline(path)["127.0.0.1"]["open_ports"], "80;443")
            with path.open() as handle:
                self.assertEqual(next(csv.DictReader(handle))["errors"], "'=unsafe")
            inv.write_report(path, [row, row])
            with self.assertRaises(ValueError):
                inv.read_baseline(path)

    def test_cli_output_and_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "report.csv"
            with patch("inventory.scan_host", return_value=dict(ip="127.0.0.1", status="no_response", open_ports="")):
                self.assertEqual(inv.main(["127.0.0.1", "--output", str(out)]), 0)
            self.assertTrue(out.exists())
            for extra in (["--timeout", "nan"], ["--workers", "0"],
                          ["--baseline", str(out), "--output", str(out)]):
                with self.assertRaises(SystemExit):
                    inv.main(["127.0.0.1", *extra])


if __name__ == "__main__":
    unittest.main()
