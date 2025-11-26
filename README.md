SME Security Misconfiguration Scanner
A lightweight security tool designed to help Small and Medium-Sized Enterprises (SMEs) identify common web-facing misconfigurations.
The scanner focuses on simple, high-impact issues frequently exploited by attackers — without requiring deep security expertise.
It provides a clear 0–100 risk score, human-readable findings, and LOW / MEDIUM / HIGH severity classification.

Features
HTTP Security Checks
•	Detects missing security headers:
  o	Content-Security-Policy
  o	Strict-Transport-Security
  o	X-Frame-Options
  o	Referrer-Policy
  o	etc
•	Checks whether the site:
  o	Uses HTTPS
  o	Forces HTTP → HTTPS redirection
  o	Is reachable over HTTP/HTTPS


| Port | Service | Risk        |
| ---- | ------- | ----------- |
| 21   | FTP     | High        |
| 22   | SSH     | Medium      |
| 23   | Telnet  | High        |
| 80   | HTTP    | Information |
| 443  | HTTPS   | Information |
| 3306 | MySQL   | High        |
| 3389 | RDP     | High        |



Sensitive Path Detection
Identifies exposed or discoverable administrative or sensitive paths such as:
    •	/admin
    •	/login
    •	/config
    •	/backup
    •	/phpmyadmin
    •	/wp-admin
Flags:
    •	200 OK — fully exposed
    •	401/403 — restricted but discoverable


| Score  | Risk   |
| ------ | ------ |
| 0–30   | LOW    |
| 31–60  | MEDIUM |
| 61–100 | HIGH   |



Installation
git clone https://github.com/yourusername/sme-security-scanner.git
cd sme-security-scanner
pip install -r requirements.txt


python cli.py --domain example.com


Example Output
=== SME SECURITY MISCONFIGURATION SCAN ===
 Scanned domain      : example.com
 Resolved URL        : https://example.com
 Uses HTTPS          : YES
 HTTP→HTTPS redirect : YES
 Target IP           : 93.184.216.34

=== RISK SCORES ===
 HTTP score          : 20
 Port score          : 25
 Path score          : 10
 Total score         : 55
 Overall risk level  : MEDIUM

=== MISSING SECURITY HEADERS ===
 - Content-Security-Policy
 - Referrer-Policy

=== OPEN PORTS DETECTED ===
 - SSH (port 22)

=== SENSITIVE PATHS ===
 - /admin (HTTP 403)

=== REASONS (HTTP) ===
 - Missing recommended security headers: Content-Security-Policy, Referrer-Policy.

=== REASONS (PORTS) ===
 - SSH (22) is exposed – ensure strong authentication and IP restrictions.

=== REASONS (PATHS) ===
 - Restricted path detectable: /admin (HTTP 403).

Scan complete.


Project Structure
scanner/
  http_checks.py         → HTTPS, headers, redirect validation
  port_checks.py         → Public IP validation, safe port scanning
  path_checks.py         → Sensitive path detection
  scoring.py             → Scoring engine for HTTP, ports, and paths
  config.py              → Central configuration for ports and paths
  logging_config.py      → Logging setup

cli.py                   → Command-line interface
tests/                   → Unit tests (pytest)
README.md





