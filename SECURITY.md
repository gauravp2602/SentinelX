# Security Policy

## CyberSentinel SOC

CyberSentinel SOC is an educational Security Operations Center (SOC) dashboard built with Python, Flask, and SQLite.

This document describes the security controls, responsible-use guidelines, and known limitations of the project.

## 1. Security Features

The application includes the following security controls:

- **Password Security:** Passwords are stored using Werkzeug password hashing.
- **CSRF Protection:** Flask-WTF CSRF protection is enabled for form submissions.
- **Login Rate Limiting:** Five failed login attempts trigger a temporary five-minute lockout.
- **Session Management:** Sessions use a 15-minute inactivity timeout.
- **Secure Cookie Settings:** HttpOnly and SameSite cookie settings are configured.
- **Role-Based Access Control:** Admin and Analyst roles have different permissions.
- **Account Management:** Administrators can activate or deactivate user accounts.
- **Audit Logging:** Important authentication and administrative actions are recorded.
- **Database Protection:** SQLite is used for local application data.

## 2. Responsible Use

CyberSentinel SOC is intended for:

- Cybersecurity learning and demonstrations.
- SOC analyst training.
- Defensive security practice.
- Local testing in authorized environments.

Do not use this application to access, monitor, or test systems without proper authorization.

## 3. Known Limitations

This project is an educational prototype, not a production-ready SIEM or enterprise SOC platform.

- Threat intelligence functionality uses offline demonstration data.
- The Network Lab performs private/loopback CIDR calculations and does not perform network scanning.
- Log Analyzer processes user-provided log text and uses demonstration event behavior.
- File Integrity functionality demonstrates SHA-256 hash generation on local demo files.
- Production deployment requires additional security review and configuration.

## 4. Reporting a Security Issue

If you discover a security vulnerability, please report it privately to the project maintainer.

Include:
- A description of the issue.
- Steps to reproduce it.
- Potential security impact.
- Relevant screenshots or logs, if available.

Avoid publicly sharing sensitive vulnerability details before they are addressed.

## 5. Security Recommendations

Before deploying this application:

- Use a strong, persistent secret key.
- Never commit passwords, API keys, or database files.
- Disable debug mode.
- Use HTTPS in production.
- Configure secure session cookies.
- Restrict administrative access.
- Keep dependencies updated.
- Back up the database securely.

## 6. Project Status

CyberSentinel SOC is an educational portfolio project. Its security features demonstrate foundational defensive security concepts and should not be considered a substitute for a professional security assessment.

---
**Project:** CyberSentinel SOC  
**Technology:** Python, Flask, SQLite, HTML, CSS, JavaScript  
**Purpose:** Cybersecurity Education and SOC Demonstration