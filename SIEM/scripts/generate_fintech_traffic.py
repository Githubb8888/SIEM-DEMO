#!/usr/bin/env python3
"""
Traffic Generator for Fintech Mini-SIEM.
Generates realistic fintech traffic with normal patterns and attack simulations.
Uses real employee and device data from the seeded database.
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage import seed_realistic_environment, get_employees, get_devices, get_db_path
from src.collector import generate_sample_traffic


def main():
    parser = argparse.ArgumentParser(
        description="Generate fintech traffic with attack patterns for SIEM testing"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1000,
        help="Number of events to generate (default: 1000)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="sample_logs/fintech_stream.jsonl",
        help="Output file path (default: sample_logs/fintech_stream.jsonl)"
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.3,
        help="Ratio of attack traffic (0.0-1.0, default: 0.3)"
    )
    parser.add_argument(
        "--seed-db",
        action="store_true",
        help="Seed the database with 75 employees and 110 devices before generating traffic"
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Reset the database before seeding (use with --seed-db)"
    )

    args = parser.parse_args()

    if not 0 <= args.attack_ratio <= 1:
        print("Error: attack-ratio must be between 0.0 and 1.0")
        sys.exit(1)

    # Seed database if requested
    if args.seed_db or args.reset_db:
        print("Seeding database with 75 employees and 110 devices...")
        emp_count, dev_count = seed_realistic_environment(reset=args.reset_db)
        print(f"Seeded {emp_count} employees and {dev_count} devices")

    # Verify database has data
    employees = get_employees()
    devices = get_devices()
    if not employees or not devices:
        print("Error: Database not seeded. Run with --seed-db first.")
        sys.exit(1)

    print(f"Database has {len(employees)} employees and {len(devices)} devices")
    print(f"Generating {args.count} events with {args.attack_ratio*100:.0f}% attack traffic...")
    print(f"Output: {args.output}")

    count = generate_sample_traffic(args.count, args.output, args.attack_ratio)

    print(f"Generated {count} events successfully!")


if __name__ == "__main__":
    main()