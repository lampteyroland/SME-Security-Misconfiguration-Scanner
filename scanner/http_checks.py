from typing import Dict, Any
import logging

import requests

log = logging.getLogger(__name__)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

USER_AGENT = "SME-Security-Scanner/0.1"


def fetch_url(url: str, timeout: int = 5) -> requests.Response | None:
    """
    Fetch a URL with a basic User-Agent and redirect support.
    Returns a `requests.Response` on success, or None on failure.
    """
    try:
        log.debug(f"Fetching URL: {url}")
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        return response
    except requests.RequestException as e:
        log.warning(f"Request failed for {url}: {e}")
        return None


def _normalise_domain(domain: str) -> str:
    """
    Best-effort normalisation of a domain input.
    - Strips scheme if present
    - Strips leading/trailing slashes and path
    """
    domain = domain.strip()
    if "://" in domain:
        domain = domain.split("://", 1)[1]

    domain = domain.split("/", 1)[0]
    return domain.strip()


def _collect_security_headers(response: requests.Response, results: Dict[str, Any]) -> None:
    """
    Populate found_headers and missing_headers in results
    based on SECURITY_HEADERS and the given response.
    """
    headers = response.headers or {}
    for header_name in SECURITY_HEADERS:
        value = headers.get(header_name)
        if value is not None:
            results["found_headers"][header_name] = value
        else:
            results["missing_headers"].append(header_name)


def check_http_headers(domain: str) -> Dict[str, Any]:
    """
    Check basic HTTP(S) security hygiene:
    - Does the site respond over HTTPS?
    - Which key security headers are present/missing?
    - Does HTTP redirect to HTTPS (if HTTP is reachable)?

    Returns a dict with:
      - url
      - found_headers
      - missing_headers
      - errors
      - uses_https
      - http_to_https_redirect
    """
    domain = _normalise_domain(domain)

    results: Dict[str, Any] = {
        "url": None,
        "found_headers": {},
        "missing_headers": [],
        "errors": [],
        "uses_https": False,
        "http_to_https_redirect": False,
    }

    def try_host(hostname: str):
        http_url = f"http://{hostname}"
        https_url = f"https://{hostname}"

        # Prefer HTTPS
        resp_https = fetch_url(https_url)
        if resp_https:
            results["url"] = resp_https.url
            results["uses_https"] = True
            _collect_security_headers(resp_https, results)
            return resp_https, http_url

        # Fall back to HTTP
        resp_http = fetch_url(http_url)
        if resp_http:
            results["url"] = resp_http.url
            _collect_security_headers(resp_http, results)
            return resp_http, http_url

        return None, http_url

    # 1. Try the given domain
    resp, http_url = try_host(domain)

    # 2. If unreachable and no www., try www.domain (SME-friendly fallback)
    if not resp and not domain.startswith("www."):
        www_domain = f"www.{domain}"
        log.info(f"Direct domain unreachable, trying {www_domain}")
        resp, http_url = try_host(www_domain)

    if not resp:
        results["errors"].append(
            f"Site unreachable over HTTP or HTTPS for {domain}"
        )
        return results

    # 3. Check if HTTP (if reachable) redirects to HTTPS
    resp_http = fetch_url(http_url)
    if resp_http:
        if resp_http.url.startswith("https://"):
            results["http_to_https_redirect"] = True
    else:
        # HTTP closed or unreachable – note this, but don't assume it's bad
        results["errors"].append(
            "HTTP (port 80) not reachable; cannot verify HTTP→HTTPS redirect."
        )

    return results
