from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys

from sisyphusgate.app import SisyphusGate
from sisyphusgate.config import load_config


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sisyphusgate",
        description="SisyphusGate - A modular honeypot system",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    run_parser = subparsers.add_parser("run", help="Start the honeypot system")
    run_parser.add_argument("--config", "-c", help="Path to configuration file", default=None)

    subparsers.add_parser("report", help="Generate a summary report")

    subparsers.add_parser("geoip-update", help="Update GeoIP database")

    subparsers.add_parser("gen-key", help="Generate SSH host key")

    return parser


async def run_command(args: argparse.Namespace) -> None:
    app = SisyphusGate(config_path=args.config)

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def signal_handler() -> None:
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await app.start()

    try:
        await shutdown_event.wait()
    finally:
        await app.stop()


def report_command() -> None:
    config = load_config()
    agg_cfg = config.sisyphusgate.aggregator

    from sisyphusgate.aggregator.collector import EventCollector
    from sisyphusgate.aggregator.geoip import GeoIPResolver
    from sisyphusgate.aggregator.reporter import Reporter

    collector = EventCollector(queue_size=agg_cfg.event_queue_size)
    geoip = GeoIPResolver(db_path=agg_cfg.geoip_db_path)

    reporter = Reporter(collector, geoip)

    print(reporter.format_summary())

    import os
    if os.path.exists(agg_cfg.jsonl_path):
        files = sorted([f for f in os.listdir(agg_cfg.jsonl_path) if f.endswith(".jsonl")], reverse=True)
        if files:
            latest = os.path.join(agg_cfg.jsonl_path, files[0])
            with open(latest, "r") as f:
                lines = f.readlines()
            print(f"\nLatest log file: {latest}")
            print(f"Entries in latest log: {len(lines)}")


def gen_key_command() -> None:
    import os
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    key_path = "data/ssh_host_key"
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(key_bytes)
    print(f"SSH host key generated: {key_path}")


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "run":
        asyncio.run(run_command(args))
    elif args.command == "report":
        report_command()
    elif args.command == "gen-key":
        gen_key_command()
    elif args.command == "geoip-update":
        print("GeoIP database update not yet implemented. Please download manually from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()