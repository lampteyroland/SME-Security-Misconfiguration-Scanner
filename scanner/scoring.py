from typing import Dict, List, Tuple, Any

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

HTTP_WEIGHTS: Dict[str, int] = {
    "unreachable": 50,
    "no_https": 30,
    "no_redirect": 15,
    "missing_header": 5,
}

PORT_WEIGHTS: Dict[str, int] = {
    "high_risk_service": 25,     # Telnet, FTP, RDP
    "db_exposed": 20,            # MySQL
    "ssh_exposed": 10,           # SSH
    "other_service": 5,          # Any other open port from default list
}

PATH_WEIGHTS: Dict[str, int] = {
    "fully_exposed": 20,         # /admin returns 200
    "restricted_visible": 10,    # /admin returns 401/403
}

# Overall maximum score used for display / risk banding
MAX_TOTAL_SCORE: int = 100


# ---------------------------------------------------------------------------
# HTTP scoring
# ---------------------------------------------------------------------------

def score_from_http(http_results: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Convert the HTTP scan results into a numerical risk score and human-readable reasons.

    Expected http_results format (produced by http_checks.check_http_headers):
        {
            "url": str | None,
            "found_headers": dict,
            "missing_headers": list[str],
            "errors": list[str],
            "uses_https": bool,
            "http_to_https_redirect": bool,
        }

    Returns:
        score (int), reasons (list[str])
    """

    score = 0
    reasons: List[str] = []

    errors = http_results.get("errors", [])

    # --- UNREACHABLE CASE (true connectivity failure only) ------------------
    # We only treat the site as "unreachable" if the errors indicate that,
    # not just because HTTP:80 is closed while HTTPS still works.
    unreachable_errors = [
        e for e in errors
        if "unreachable" in e.lower()
    ]

    if unreachable_errors:
        score += HTTP_WEIGHTS["unreachable"]
        reasons.append("Site is unreachable over HTTP or HTTPS.")
        # No point checking further if the host can't be reached at all
        return min(score, MAX_TOTAL_SCORE), reasons

    # --- HTTPS USAGE --------------------------------------------------------
    uses_https = http_results.get("uses_https", False)
    if not uses_https:
        score += HTTP_WEIGHTS["no_https"]
        reasons.append(
            "The site does not use HTTPS by default, meaning traffic may be exposed "
            "to interception or tampering."
        )

    # --- HTTP → HTTPS REDIRECT ----------------------------------------------
    http_to_https_redirect = http_results.get("http_to_https_redirect", False)
    if not http_to_https_redirect:
        score += HTTP_WEIGHTS["no_redirect"]
        reasons.append(
            "HTTP traffic does not redirect to HTTPS, leaving unencrypted access open."
        )

    # --- SECURITY HEADERS ---------------------------------------------------
    missing_headers = http_results.get("missing_headers", [])
    if missing_headers:
        penalty = HTTP_WEIGHTS["missing_header"] * len(missing_headers)
        score += penalty
        reasons.append(
            "Missing recommended security headers: "
            + ", ".join(missing_headers)
            + "."
        )

    return min(score, MAX_TOTAL_SCORE), reasons


# ---------------------------------------------------------------------------
# Port scoring
# ---------------------------------------------------------------------------

def score_from_ports(port_results: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Score risk based on exposed ports.

    Expected port_results format (from port_checks.scan_ports):
        {
            "target_domain": str,
            "target_ip": str | None,
            "open_ports": [
                {"port": int, "service": str},
                ...
            ],
            "errors": list[str],
        }

    Returns:
        score (int), reasons (list[str])
    """
    score = 0
    reasons: List[str] = []

    errors = port_results.get("errors", [])
    if errors:
        # DNS failure or similar – we log it but don't double-count reachability;
        # HTTP scoring already penalises unreachable sites.
        reasons.extend(errors)
        return score, reasons

    open_ports = port_results.get("open_ports", [])
    if not open_ports:
        # No open ports from our list – no added risk from this module.
        return score, reasons

    for entry in open_ports:
        port = entry.get("port")
        service = (entry.get("service") or "").upper()

        if port in (21, 23, 3389):  # FTP, Telnet, RDP
            score += PORT_WEIGHTS["high_risk_service"]
            reasons.append(
                f"High-risk service exposed: {service} (port {port})."
            )
        elif port == 3306:          # MySQL
            score += PORT_WEIGHTS["db_exposed"]
            reasons.append(
                "Database port MySQL (3306) is exposed to the internet."
            )
        elif port == 22:            # SSH
            score += PORT_WEIGHTS["ssh_exposed"]
            reasons.append(
                "SSH (22) is exposed – ensure strong authentication and IP restrictions."
            )
        else:
            score += PORT_WEIGHTS["other_service"]
            reasons.append(
                f"Service {service or 'unknown'} (port {port}) is exposed."
            )

    return score, reasons


# ---------------------------------------------------------------------------
# Path scoring
# ---------------------------------------------------------------------------

def score_from_paths(path_results: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Score exposed admin/sensitive paths.
    Each suspicious path increases risk.

    Expected path_results format (from path_checks.check_sensitive_paths):
        {
            "checked_paths": [...],
            "suspicious": [
                {"path": str, "status": int},
                ...
            ],
            "errors": list[str],
        }
    """

    score = 0
    reasons: List[str] = []

    suspicious = path_results.get("suspicious", [])
    if not suspicious:
        return score, reasons

    for entry in suspicious:
        path = entry["path"]
        status = entry["status"]

        # 200 means fully exposed — biggest risk
        if status == 200:
            score += PATH_WEIGHTS["fully_exposed"]
            reasons.append(f"Sensitive path exposed: {path} (HTTP 200).")

        # 401 or 403 = protected but visible (still leaks information)
        elif status in (401, 403):
            score += PATH_WEIGHTS["restricted_visible"]
            reasons.append(
                f"Restricted path detectable: {path} (HTTP {status})."
            )

    return score, reasons


# ---------------------------------------------------------------------------
# Overall risk level helper
# ---------------------------------------------------------------------------

def risk_level(score: int) -> str:
    """
    Map a numerical score onto a human-friendly risk band.

    Thresholds are intentionally simple and SME-friendly.
    """
    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    else:
        return "HIGH"


# ---------------------------------------------------------------------------
# Combine multiple module scores
# ---------------------------------------------------------------------------

def combine_scores(*scores: int) -> int:
    """
    Combine scores from multiple modules and cap at MAX_TOTAL_SCORE.

    Usage:
        total = combine_scores(http_score, port_score, path_score, tls_score, ...)
    """
    total = sum(scores)
    return min(total, MAX_TOTAL_SCORE)
