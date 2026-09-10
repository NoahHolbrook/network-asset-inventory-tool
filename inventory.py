"""Bounded IPv4 inventory scans using only the Python standard library."""
import argparse
import csv
import errno
import ipaddress
import math
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ["scanned_at", "ip", "status", "open_ports", "ping", "errors", "change"]


def targets(value):
    network = ipaddress.IPv4Network(value, strict=False)
    if network.num_addresses > 4096:
        raise ValueError("Use a network with at most 4096 addresses (/20 or smaller).")
    return [str(address) for address in network.hosts()]


def ports(value):
    result = sorted({int(part.strip()) for part in value.split(",")})
    if not result or len(result) > 64 or any(p < 1 or p > 65535 for p in result):
        raise ValueError("Specify 1–64 comma-separated ports between 1 and 65535.")
    return result


def ping_host(ip, timeout):
    # IP comes from IPv4Network, and shell=False keeps arguments out of a shell.
    command = ["ping", "-n" if platform.system() == "Windows" else "-c", "1", ip]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return ("reply", "") if result.returncode == 0 else ("no_reply", "")
    except FileNotFoundError:
        return "unavailable", "ping executable missing"
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except OSError as exc:
        return "error", f"ping: {exc}"


def scan_host(ip, selected_ports, timeout=0.5, use_ping=False):
    opened, errors = [], []
    responded = False
    for port in selected_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect((ip, port))
                opened.append(port)
                responded = True
        except ConnectionRefusedError:
            # A refusal is evidence of a responding endpoint, not an open service.
            responded = True
        except (TimeoutError, socket.timeout):
            pass
        except OSError as exc:
            if exc.errno in (errno.ECONNREFUSED, 10061):
                responded = True
            else:
                errors.append(f"{port}: {exc}")
    ping, ping_error = ping_host(ip, timeout) if use_ping else ("disabled", "")
    if ping_error:
        errors.append(ping_error)
    return dict(scanned_at=datetime.now(timezone.utc).isoformat(), ip=ip,
                status="responding" if responded or ping == "reply" else "no_response",
                open_ports=";".join(map(str, opened)), ping=ping,
                errors=" | ".join(errors), change="not_compared")


def read_baseline(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not {"ip", "status", "open_ports"}.issubset(reader.fieldnames or []):
            raise ValueError("Baseline must contain ip, status, and open_ports columns.")
        result = {}
        for row in reader:
            if not row.get("ip") or row.get("status") not in ("responding", "no_response"):
                raise ValueError("Invalid baseline row.")
            ip = str(ipaddress.IPv4Address(row["ip"]))
            raw_ports = row.get("open_ports")
            if raw_ports is None:
                raise ValueError("Missing open_ports value.")
            row["open_ports"] = ";".join(map(str, ports(raw_ports.replace(";", ",")))) if raw_ports else ""
            if ip in result:
                raise ValueError(f"Duplicate baseline IP: {ip}")
            result[ip] = row
        return result


def compare(rows, baseline):
    for row in rows:
        old = baseline.get(row["ip"])
        if old is None:
            row["change"] = "new_address"
        elif row["status"] != old["status"]:
            row["change"] = "response_changed"
        elif row["open_ports"] != old["open_ports"]:
            row["change"] = "ports_changed"
        else:
            row["change"] = "unchanged"
    return rows


def write_report(path, rows):
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        # Escape externally supplied text so spreadsheet apps do not evaluate it.
        for row in rows:
            writer.writerow({k: "'" + str(v) if str(v).startswith(("=", "+", "-", "@")) else v
                             for k, v in row.items()})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inventory an IPv4 network you own or administer.")
    parser.add_argument("network", help="IPv4 address or CIDR, e.g. 127.0.0.1/32")
    parser.add_argument("--ports", default="22,80,443,3389")
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--ping", action="store_true", help="Also run the OS ping utility")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path, default=Path("inventory.csv"))
    args = parser.parse_args(argv)
    try:
        addresses, selected = targets(args.network), ports(args.ports)
        if not math.isfinite(args.timeout) or not 0 < args.timeout <= 10:
            raise ValueError("timeout must be greater than 0 and at most 10 seconds")
        if not 1 <= args.workers <= 128:
            raise ValueError("workers must be between 1 and 128")
        if args.baseline and args.baseline.resolve() == args.output.resolve():
            raise ValueError("Output must not overwrite the baseline.")
        baseline = read_baseline(args.baseline) if args.baseline else None
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            rows = list(executor.map(lambda ip: scan_host(ip, selected, args.timeout, args.ping), addresses))
        if baseline is not None:
            compare(rows, baseline)
        write_report(args.output, rows)
    except (ValueError, OSError, csv.Error) as exc:
        parser.error(str(exc))
    responding = sum(row["status"] == "responding" for row in rows)
    print(f"Scanned {len(rows)} addresses; {responding} responding. Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
