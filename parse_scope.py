#!/usr/bin/env python3
"""Normalize generic bug-bounty scope CSV exports into authorized web domains."""
from __future__ import annotations

import argparse
from pathlib import Path

from scope_normalization import allowed_hosts, normalize_scope_files, write_normalized_scope


def write_lines(path: str, values: set[str]) -> None:
    Path(path).write_text("".join(f"{value}\n" for value in sorted(values)), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize bug-bounty scope CSV exports conservatively")
    parser.add_argument("csv_files", nargs="+", help="One or more scope CSV exports")
    parser.add_argument("-o", "--output", default="domains.txt", help="In-scope root/domain output")
    parser.add_argument("--wildcards-output", default="wildcard_domains.txt")
    parser.add_argument("--excluded-output", default="excluded_rows.txt")
    parser.add_argument("--normalized-output", default="normalized_scope.json")
    parser.add_argument("--platform", default="", help="Optional source platform label applied to this import")
    parser.add_argument("--bounty-only", action="store_true", help="Require an explicit bounty or submission eligibility flag")
    # Retained for original callers. It never widens the safely mapped web scope.
    parser.add_argument("--include-types", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()

    records = normalize_scope_files(args.csv_files, platform=args.platform, bounty_only=args.bounty_only)
    exact, wildcards = allowed_hosts(records)
    domains = exact | wildcards
    write_lines(args.output, domains)
    write_lines(args.wildcards_output, wildcards)
    write_normalized_scope(records, args.normalized_output)

    excluded = [record for record in records if not record.web_target]
    with Path(args.excluded_output).open("w", encoding="utf-8") as handle:
        handle.write("identifier\tasset_type\tsource_platform\tsource_row\treason\n")
        for record in excluded:
            handle.write(
                f"{record.identifier}\t[{record.asset_type}]\t{record.source_platform}\t"
                f"{record.source_row}\t{record.exclusion_reason or 'not a web target'}\n"
            )

    print(f"[+] {len(domains)} in-scope web domain(s) written to {args.output}")
    print(f"[+] {len(wildcards)} wildcard root domain(s) written to {args.wildcards_output}")
    print(f"[+] normalized scope records: {len(records)} -> {args.normalized_output}")
    print(f"[+] {len(excluded)} excluded/out-of-scope row(s) -> {args.excluded_output}")


if __name__ == "__main__":
    main()
