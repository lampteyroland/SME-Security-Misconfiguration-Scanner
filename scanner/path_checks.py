import logging
import requests
from typing import List, Dict, Any
from scanner.config import SENSITIVE_PATHS  # <-- importing from config.py

log = logging.getLogger(__name__)


def check_sensitive_paths(domain: str,
                          paths: List[str] | None = None,
                          timeout: int = 5) -> Dict[str, Any]:
    """
    Check if sensitive/administrative paths return suspicious HTTP response codes.

    A path is considered suspicious if:
    - It returns HTTP 200 (page exists)
    - It returns 401/403 (restricted but accessible enough to enumerate)

    Returns:
        {
            "checked_paths": [...],
            "suspicious": [
                {"path": "/admin", "status": 200},
                ...
            ],
            "errors": [],
        }
    """
    # Use config-defined paths if none given
    if paths is None:
        paths = SENSITIVE_PATHS

    results: Dict[str, Any] = {
        "checked_paths": paths,
        "suspicious": [],
        "errors": [],
    }

    # Prefer HTTPS; fall back to HTTP if needed
    base_urls = [
        f"https://{domain}",
        f"http://{domain}"
    ]

    for p in paths:
        tested = False

        for base in base_urls:
            url = base + p
            log.debug(f"Checking sensitive path: {url}")

            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                status = resp.status_code
                tested = True

                # These statuses mean the path exists or leaks its presence
                if status in (200, 401, 403):
                    log.info(f"Sensitive path detected: {p} (HTTP {status})")
                    results["suspicious"].append({
                        "path": p,
                        "status": status,
                    })
                    break  # No need to test the HTTP fallback if HTTPS found

            except requests.RequestException as e:
                log.warning(f"Failed to access {url}: {e}")
                continue

        if not tested:
            # None of the base URLs worked
            results["errors"].append(f"Failed to evaluate path: {p}")

    return results
