import logging
import socket
import ipaddress
from typing import Dict, Any

from scanner.config import DEFAULT_PORTS  # ports now come from config.py

log = logging.getLogger(__name__)


def resolve_domain(domain: str) -> str | None:
    """
    Resolve a domain to an IPv4 address.
    Returns the IP as a string, or None if resolution fails.
    """
    try:
        ip = socket.gethostbyname(domain)
        log.debug(f"Resolved domain {domain!r} to IP {ip}")
        return ip
    except socket.gaierror as e:
        log.warning(f"Failed to resolve domain {domain!r}: {e}")
        return None


def is_public_ip(ip: str) -> bool:
    """
    Check whether an IP address is public (not private/loopback/reserved).

    This is a safety guard to discourage scanning internal infrastructure
    by accident. You can relax this if you explicitly want internal scans.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved)
    except ValueError:
        return False


def scan_ports(
    domain: str,
    ports: Dict[int, str] | None = None,
    timeout: float = 0.5,
) -> Dict[str, Any]:
    """
    Scan a small set of TCP ports on the target.

    Args:
        domain: Domain name to resolve and scan.
        ports: Optional mapping of port -> service name. If None, uses DEFAULT_PORTS.
        timeout: Socket timeout per connection attempt in seconds.

    Returns:
        {
            "target_domain": str,
            "target_ip": str | None,
            "open_ports": [
                {"port": int, "service": str},
                ...
            ],
            "errors": list[str],
        }
    """
    if ports is None:
        ports = DEFAULT_PORTS

    results: Dict[str, Any] = {
        "target_domain": domain,
        "target_ip": None,
        "open_ports": [],
        "errors": [],
    }

    ip = resolve_domain(domain)
    if not ip:
        results["errors"].append("Could not resolve domain to IP address.")
        return results

    if not is_public_ip(ip):
        msg = f"Target IP {ip} for {domain!r} is not a public address; skipping port scan."
        log.warning(msg)
        results["errors"].append(msg)
        results["target_ip"] = ip
        return results

    results["target_ip"] = ip
    log.info(f"Starting port scan for {domain!r} ({ip}) on {len(ports)} ports")

    for port, service in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            log.debug(f"Checking {service} (port {port}) on {ip}")
            conn_result = sock.connect_ex((ip, port))
            if conn_result == 0:
                log.info(f"Port open: {service} (port {port}) on {ip}")
                results["open_ports"].append({"port": port, "service": service})
        except OSError as e:
            log.warning(f"Error scanning port {port} on {ip}: {e}")
        finally:
            sock.close()

    return results
