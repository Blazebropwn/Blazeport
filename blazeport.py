#!/usr/bin/env python3
"""BlazePort: small TCP port scanner for authorized security testing."""

from __future__ import annotations

import argparse
import csv
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import islice
from pathlib import Path


@dataclass(frozen=True)
class ScanResult:
    host: str
    ip: str
    port: int
    service: str
    banner: str = ""


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, ip: str, port: int, timeout: float, probe: str) -> ScanResult | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = ""
            if probe != "none":
                sock.settimeout(timeout)
                try:
                    if probe == "http":
                        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    banner = sock.recv(1024).decode(errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
            return ScanResult(host, ip, port, service_name(port), banner)
    except (ConnectionRefusedError, TimeoutError, socket.timeout, OSError):
        return None


def save_results(results: list[ScanResult], prefix: str) -> tuple[Path, Path]:
    txt_path = Path(f"{prefix}.txt")
    csv_path = Path(f"{prefix}.csv")
    with txt_path.open("w", encoding="utf-8") as handle:
        handle.write("BlazePort scan results\n")
        for result in results:
            suffix = f" | {result.banner}" if result.banner else ""
            handle.write(f"{result.ip}:{result.port} | {result.service}{suffix}\n")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Host", "IP", "Port", "Service", "Banner"])
        for result in results:
            writer.writerow([result.host, result.ip, result.port, result.service, result.banner])
    return txt_path, csv_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Concurrent TCP port scanner for systems you own or are authorized to test.")
    parser.add_argument("--target", required=True, help="Target hostname or IPv4 address")
    parser.add_argument("--start-port", type=int, default=1, help="First port (default: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="Last port (default: 1024)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds")
    parser.add_argument("--workers", type=int, default=100, help="Maximum concurrent workers")
    parser.add_argument("--probe", choices=("none", "passive", "http"), default="none", help="Optional banner probe")
    parser.add_argument("--output", help="Optional output filename prefix")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= args.start_port <= 65535:
        parser.error("--start-port must be between 1 and 65535")
    if not 1 <= args.end_port <= 65535:
        parser.error("--end-port must be between 1 and 65535")
    if args.start_port > args.end_port:
        parser.error("--start-port cannot be greater than --end-port")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not 1 <= args.workers <= 500:
        parser.error("--workers must be between 1 and 500")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    try:
        addresses = socket.getaddrinfo(args.target, None, type=socket.SOCK_STREAM)
        ip = addresses[0][4][0]
    except socket.gaierror as exc:
        parser.error(f"Could not resolve target: {exc}")
    print(f"Scanning {args.target} ({ip}) ports {args.start_port}-{args.end_port}")
    print("Use only on systems you own or have explicit permission to test.\n")
    results: list[ScanResult] = []
    ports = iter(range(args.start_port, args.end_port + 1))
    batch_size = args.workers * 2
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        while batch := list(islice(ports, batch_size)):
            futures = [executor.submit(scan_port, args.target, ip, port, args.timeout, args.probe) for port in batch]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                    suffix = f" | {result.banner}" if result.banner else ""
                    print(f"OPEN {result.port:<5} {result.service}{suffix}")
    results.sort(key=lambda item: item.port)
    print(f"\nFound {len(results)} open port(s).")
    if args.output:
        txt_path, csv_path = save_results(results, args.output)
        print(f"Saved: {txt_path} and {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
