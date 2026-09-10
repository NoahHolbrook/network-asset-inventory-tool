# Network Asset Inventory Tool

A Python command-line project that inventories responding IPv4 endpoints and selected TCP ports, exports CSV, and compares results against an earlier scan. Uses sockets, bounded worker threads, and optionally the operating system's ping command. No third-party packages required.

## Run

Requires Python 3.10 or newer. From this directory:

```sh
python inventory.py 127.0.0.1/32 --ports 22,80,443 --output first.csv
python inventory.py 127.0.0.1/32 --ports 22,80,443 --baseline first.csv --output second.csv
```

On Windows, use `py` if `python` is unavailable. For your own LAN, substitute its CIDR (for example `192.168.1.0/24`). Scan only networks you own or have permission to administer. `--workers 32` bounds parallel hosts; `--timeout 0.5` bounds each TCP attempt. `--ping` adds an optional ping subprocess with the same timeout. Missing ping utilities and permission errors are recorded instead of crashing the scan.

## How it works

1. Parse and validate the IPv4 range and selected ports. Limit ranges to 4096 addresses and port lists to 64 ports.
2. Submit hosts to a thread pool. Each host tries its ports in order using sockets with timeouts.
3. Mark a host responding when a connection succeeds, a connection is explicitly refused, or ping replies. Silence is reported as `no_response`, not proof a device is offline.
4. Compare status and open port sets with an optional baseline.
5. Write timestamps, IPs, observed ports, ping results, errors, and change labels to CSV in numeric IP order.

`new_address` means the address was absent from the baseline. `response_changed` and `ports_changed` describe observations. They do **not** establish unauthorized access or actual device configuration changes: firewalls, scan settings, and transient outages can change results. Use identical ranges and port lists when comparing. Baseline-only addresses outside the new scan are not evaluated.

This is a small inventory aid, not full asset management: it does not identify MAC addresses, operating systems, installed software, or device ownership. A responding intermediary can also produce a refusal. No measured claims about business time savings or inventory accuracy are made.

## Test

```sh
python -m unittest discover -s tests -v
```

Tests cover a real loopback TCP listener, input validation, connection failures, ping failures, CSV escaping, and baseline comparison. Tests do not scan your LAN.

## Files

- `inventory.py`: scanner, CSV reporting, comparison, and CLI.
- `tests/test_inventory.py`: automated tests.
- `examples/baseline.csv`: fictional input showing the baseline format.

Created as an AI-assisted portfolio learning project. Review the code and reproduce results before discussing performance in an interview.
