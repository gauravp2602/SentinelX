# SentinelX — Cybersecurity Learning & Monitoring Platform

SentinelX is a local, educational Flask application with authentication, security utilities,
basic DNS/TLS inspection, log triage, and a tightly restricted private-LAN TCP checker.

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Setup (Windows PowerShell)
```powershell
cd Desktop\SentinelX
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000` manually in your browser and register an account.

## Setup (macOS/Linux)
```bash
cd ~/Desktop/SentinelX
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Included modules
- Local user registration/login with Werkzeug password hashing
- Dashboard and per-user activity log
- Password composition audit (does not store submitted password)
- SHA-256 and SHA-512 hash generator
- Heuristic URL/phishing indicator analyzer
- DNS A/AAAA/MX/NS/TXT lookup
- TLS certificate inspection
- Security log pattern analyzer
- TCP port checks limited to private IPv4/IPv6 LAN addresses, ports 1–1024, max 20 ports, and explicit authorization confirmation

## Safety and limitations
- Only test systems and networks you own or have explicit permission to assess.
- The network checker intentionally refuses public IP addresses and hostnames.
- URL analysis is heuristic and is not a reputation feed or a definitive verdict.
- This is a learning/portfolio project, not a production SOC or enterprise IDS.
- Do not expose Flask's development server to the public internet.
- Before deployment: set a strong random `SECRET_KEY`, use HTTPS, set `COOKIE_SECURE=1`,
  add CSRF protection and rate limiting, configure a production WSGI server, and perform
  a security review.

## Database
SQLite database is created automatically at `database/sentinelx.db` on first run.
