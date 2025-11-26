DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

SENSITIVE_PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/backup",
    "/config",
    "/phpmyadmin",
    "/wp-admin",
]
