import sys
import argparse
import logging
from typing import Any, Dict, List
from urllib.parse import urlparse

from scanner.logging_config import configure_logging
from scanner.http_checks import check_http_headers
from scanner.port_checks import scan_ports
from scanner.path_checks import check_sensitive_paths
from scanner.scoring import (
    score_from_http,
    score_from_ports,
    score_from_paths,
    combine_scores,
    risk_level,
)


def normalise_domain(raw: str) -> str:
    """
    Best-effort normalisation of user input into a hostname.
    Accepts things like:
      - example.com
      - https://example.com
      - https://example.com/path
    and returns just 'example.com'.
    """
    raw = raw.strip()
    if not raw:
        return ""

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    domain = parsed.netloc or parsed.path

    # Remove path/query fragments
    domain = domain.split("/", 1)[0]
    return domain.strip()


def print_results(
    domain: str,
    http_results: Dict[str, Any],
    port_results: Dict[str, Any],
    path_results: Dict[str, Any],
    http_score: int,
    port_score: int,
    path_score: int,
    total_score: int,
    http_reasons: List[str],
    port_reasons: List[str],
    path_reasons: List[str],
) -> None:

    level = risk_level(total_score)

    print("\n=== SME SECURITY MISCONFIGURATION SCAN ===")
    print(f" Scanned domain      : {domain}")
    print(f" Resolved URL        : {http_results.get('url') or 'N/A'}")
    print(f" Uses HTTPS          : {'YES' if http_results.get('uses_https') else 'NO'}")
    print(
        " HTTP→HTTPS redirect : "
        f"{'YES' if http_results.get('http_to_https_redirect') else 'NO / UNKNOWN'}"
    )

    target_ip = port_results.get("target_ip")
    print(f" Target IP           : {target_ip or 'N/A'}")

    print("\n=== RISK SCORES ===")
    print(f" HTTP score          : {http_score}")
    print(f" Port score          : {port_score}")
    print(f" Path score          : {path_score}")
    print(f" Total score         : {total_score}")
    print(f" Overall risk level  : {level}")

    # ---------------- ERRORS ----------------
    if http_results.get("errors") or port_results.get("errors"):
        print("\n=== ERRORS / WARNINGS ===")
        for err in http_results.get("errors", []):
            print(f" - {err}")
        for err in port_results.get("errors", []):
            print(f" - {err}")

    # ---------------- MISSING HEADERS ----------------
    missing = http_results.get("missing_headers") or []
    if missing:
        print("\n=== MISSING SECURITY HEADERS ===")
        for h in missing:
            print(f" - {h}")

    # ---------------- OPEN PORTS ----------------
    open_ports = port_results.get("open_ports") or []
    if open_ports:
        print("\n=== OPEN PORTS DETECTED ===")
        for entry in open_ports:
            port = entry.get("port")
            service = entry.get("service") or "unknown"
            print(f" - {service} (port {port})")

    # ---------------- SENSITIVE PATHS ----------------
    suspicious_paths = path_results.get("suspicious") or []
    print("\n=== SENSITIVE PATHS ===")
    if suspicious_paths:
        for entry in suspicious_paths:
            print(f" - {entry['path']} (HTTP {entry['status']})")
    else:
        print(" - No sensitive/admin paths detected.")

    # ---------------- REASONS ----------------
    print("\n=== REASONS (HTTP) ===")
    if http_reasons:
        for r in http_reasons:
            print(f" - {r}")
    else:
        print(" - No HTTP-related misconfigurations detected.")

    print("\n=== REASONS (PORTS) ===")
    if port_reasons:
        for r in port_reasons:
            print(f" - {r}")
    else:
        print(" - No risky open ports detected from the default list.")

    print("\n=== REASONS (PATHS) ===")
    if path_reasons:
        for r in path_reasons:
            print(f" - {r}")
    else:
        print(" - No sensitive/admin path issues detected.")

    print("\nScan complete.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SME Security Misconfiguration Scanner"
    )
    parser.add_argument(
        "--domain",
        help="Domain to scan (e.g. example.co.uk). If omitted, you will be prompted.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv).",
    )
    args = parser.parse_args()

    configure_logging(args.verbose)
    log = logging.getLogger(__name__)

    if args.domain:
        raw_input_domain = args.domain
    else:
        try:
            raw_input_domain = input(
                "Enter a domain (e.g. example.co.uk or https://example.co.uk): "
            )
        except KeyboardInterrupt:
            print("\nAborted by user.")
            sys.exit(1)

    domain = normalise_domain(raw_input_domain)
    log.debug(f"Normalised domain: {domain!r}")

    if not domain:
        print("No valid domain provided. Please try again, e.g. 'example.co.uk'.")
        sys.exit(1)

    print(f"\nScanning {domain}...\n")

    # 1) HTTP / HTTPS checks
    http_results = check_http_headers(domain)
    http_score, http_reasons = score_from_http(http_results)

    # 2) Port checks
    port_results = scan_ports(domain)
    port_score, port_reasons = score_from_ports(port_results)

    # 3) Sensitive path scanning
    path_results = check_sensitive_paths(domain)
    path_score, path_reasons = score_from_paths(path_results)

    # 4) Combine all scores
    total_score = combine_scores(http_score, port_score, path_score)

    print_results(
        domain=domain,
        http_results=http_results,
        port_results=port_results,
        path_results=path_results,
        http_score=http_score,
        port_score=port_score,
        path_score=path_score,
        total_score=total_score,
        http_reasons=http_reasons,
        port_reasons=port_reasons,
        path_reasons=path_reasons,
    )


if __name__ == "__main__":
    main()
