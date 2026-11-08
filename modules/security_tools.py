import re, socket, ssl, hashlib, ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone

def password_audit(value):
    if not value:
        return {"score": 0, "label": "No password entered", "checks": ["Enter a password to audit."]}
    checks = [
        ("At least 12 characters", len(value) >= 12),
        ("Contains lowercase letters", bool(re.search(r"[a-z]", value))),
        ("Contains uppercase letters", bool(re.search(r"[A-Z]", value))),
        ("Contains numbers", bool(re.search(r"\d", value))),
        ("Contains symbols", bool(re.search(r"[^A-Za-z0-9]", value))),
        ("Not a common password", value.lower() not in {"password", "password123", "admin123", "qwerty123", "1234567890"})
    ]
    score = sum(ok for _, ok in checks)
    label = "Strong" if score >= 5 and len(value) >= 12 else "Moderate" if score >= 3 else "Weak"
    return {"score": score, "label": label, "checks": [f"{'✓' if ok else '✗'} {name}" for name, ok in checks],
            "note": "This is a basic local heuristic, not a password breach check. Never reuse passwords."}

def hash_text(value):
    raw = value.encode("utf-8")
    return {"SHA-256": hashlib.sha256(raw).hexdigest(), "SHA-512": hashlib.sha512(raw).hexdigest(),
            "note": "Cryptographic hashes are one-way digests; do not use plain fast hashes to store passwords."}

def analyze_url(value):
    value = value.strip()
    parsed = urlparse(value if "://" in value else "http://" + value)
    findings = []
    if parsed.scheme != "https": findings.append("URL does not use HTTPS.")
    if not parsed.hostname: return {"error": "Enter a valid hostname or URL."}
    host = parsed.hostname.lower()
    if "@" in parsed.netloc: findings.append("Contains an @ symbol in the authority section.")
    if len(host) > 50: findings.append("Unusually long hostname.")
    if host.startswith("xn--") or ".xn--" in host: findings.append("Contains an internationalized/punycode hostname.")
    if re.search(r"\d+\.\d+\.\d+\.\d+", host): findings.append("Uses an IP address instead of a domain name.")
    suspicious_words = ["login", "verify", "secure", "account", "update", "password", "wallet"]
    hits = [word for word in suspicious_words if word in (host + parsed.path).lower()]
    if hits: findings.append("Sensitive-themed words present: " + ", ".join(hits))
    if len(parsed.path) > 100: findings.append("Unusually long URL path.")
    if not findings: findings.append("No basic heuristic indicators found.")
    return {"hostname": host, "scheme": parsed.scheme, "findings": findings,
            "verdict": "Review required" if len(findings) >= 2 else "No obvious indicators",
            "note": "Heuristic only. It cannot prove a URL is safe or malicious. Do not open suspicious links."}

def dns_lookup(domain):
    domain = domain.strip().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", domain):
        return {"error": "Enter a valid domain name."}
    result = {"domain": domain, "records": {}}
    try:
        result["records"]["A / IPv4"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception as e: result["records"]["A / IPv4"] = [str(e)]
    try:
        result["records"]["AAAA / IPv6"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception as e: result["records"]["AAAA / IPv6"] = ["No IPv6 result / lookup unavailable"]
    try:
        import dns.resolver
        for kind in ("MX", "NS", "TXT"):
            try: result["records"][kind] = [str(r) for r in dns.resolver.resolve(domain, kind, lifetime=3)]
            except Exception: result["records"][kind] = ["No record or lookup unavailable"]
    except ImportError:
        result["records"]["MX / NS / TXT"] = ["Install dnspython to query these record types."]
    return result

def ssl_inspect(hostname):
    hostname = hostname.strip()
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", hostname) or ".." in hostname:
        return {"error": "Enter a valid hostname only (without https:// or a path)."}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "hostname": hostname,
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore", "Unknown"),
                    "not_after": cert.get("notAfter", "Unknown"),
                    "note": "Certificate validation was performed by Python's default trust store."
                }
    except Exception as e:
        return {"error": f"TLS connection failed: {e}"}

def scan_private_host(host, ports, consent):
    if not consent:
        return {"error": "Confirm that you own or are authorized to test this device/network."}
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return {"error": "Use a literal private IP address, for example 192.168.1.10."}
    if not (ip.is_private and not ip.is_loopback and not ip.is_link_local):
        return {"error": "Only private LAN IP addresses are allowed by this tool."}
    try:
        port_list = sorted({int(p.strip()) for p in ports.split(",") if p.strip()})
    except ValueError:
        return {"error": "Ports must be comma-separated numbers."}
    if not port_list or len(port_list) > 20 or any(p < 1 or p > 1024 for p in port_list):
        return {"error": "Enter 1–20 ports in the range 1–1024."}
    results = []
    for port in port_list:
        sock = socket.socket()
        sock.settimeout(0.6)
        try:
            status = "Open" if sock.connect_ex((str(ip), port)) == 0 else "Closed / filtered"
        except OSError:
            status = "Unreachable"
        finally:
            sock.close()
        results.append({"port": port, "status": status})
    return {"host": str(ip), "results": results,
            "note": "TCP connect checks only; closed/filtered does not distinguish firewall filtering from a closed service."}

def analyze_log_text(value):
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if len(lines) > 500:
        return {"error": "Please limit the input to 500 lines."}
    patterns = {
        "Failed login indicators": re.compile(r"failed password|authentication failure|login failed|invalid user", re.I),
        "Access denied indicators": re.compile(r"access denied|permission denied|unauthorized|403", re.I),
        "Error indicators": re.compile(r"\berror\b|\bcritical\b|\bfatal\b", re.I),
        "Possible scanning indicators": re.compile(r"connection refused|port scan|too many connections", re.I)
    }
    counts, samples = {}, {}
    for label, pattern in patterns.items():
        matches = [line[:240] for line in lines if pattern.search(line)]
        counts[label] = len(matches)
        samples[label] = matches[:5]
    return {"lines_analyzed": len(lines), "counts": counts, "samples": samples,
            "note": "Pattern-based triage only. Validate findings against the full system context."}
