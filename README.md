
# CyberSentinel SOC — Advanced Cybersecurity Portfolio Project

A local, educational Security Operations Center (SOC) dashboard built using Python, Flask and SQLite. It simulates common SOC analyst workflows, including security event monitoring, incident management, offline threat intelligence, log analysis, file integrity monitoring, network calculations, audit logging and reporting.

The project also includes user authentication, role-based access control and an Admin Panel for managing users.

## Features

### SOC Monitoring
- Security overview dashboard.
- Event severity statistics and telemetry feed.
- Security event filtering and resolution workflow.
- Incident creation and status tracking.
- Audit trail for important user activities.

### Security Analysis
- Offline IP indicator lookup using reserved documentation IP ranges.
- Log analyzer for failed authentication, denied/blocked activity, errors and IPv4 patterns.
- SHA-256 file integrity baselining for submitted text.
- Private and loopback CIDR subnet calculator.
- CSV event report export.

### User and Admin Management
- User registration and login.
- Secure password hashing using Werkzeug.
- Admin and Analyst roles.
- Admin Panel with user statistics.
- User activation and deactivation.
- User role management.
- Protection against unauthorized admin operations.

### Application Security
- CSRF protection using Flask-WTF.
- Persistent SQLite-based login rate limiting.
- Five failed login attempts trigger a five-minute lockout.
- 15-minute session timeout.
- HTTPOnly and SameSite session cookie settings.
- Audit logging for important activities.
- Protected routes for authenticated users.

### Interface
- Responsive dark SOC-style dashboard.
- Sidebar navigation.
- Dashboard cards and charts.
- User-friendly forms and tables.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| SQLite | Database |
| HTML5 | Page structure |
| CSS3 | Styling and responsive design |
| JavaScript | Frontend interactions |
| Werkzeug | Password hashing |
| Flask-WTF | CSRF protection |
| SHA-256 | File integrity hashing |

## Requirements

- Python 3.10 or newer
- pip
- VS Code (recommended)
- Windows 10/11 or compatible operating system

## Installation on Windows

Open PowerShell and execute:

```powershell
cd "C:\Users\Admin\Desktop\CyberSentinel_SOC_Complete\CyberSentinel_SOC"

py -m venv .venv

.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip

pip install -r requirements.txt

python app.py
```

Open the application in your browser:

http://127.0.0.1:5000

### If PowerShell blocks virtual environment activation

Run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

.\.venv\Scripts\Activate.ps1
```

Then start the application:

```powershell
python app.py
```

## Database

The application uses SQLite.

Database location:

```text
data/cybersentinel.db
```

The database stores information such as:
- User accounts and roles.
- Security events.
- Incident records.
- Audit history.
- Login attempt and lockout information.

**Important:** Do not delete the database to reset the application unless you have created a backup. Deleting it can remove existing users and project records.

## Suggested Demo Workflow

1. Log in using an authorized account.
2. Review the SOC Overview dashboard.
3. Open Security Events and filter events by severity.
4. Resolve a security event.
5. Create an incident and update its status.
6. Open Threat Intelligence and check `203.0.113.77` as an offline demo indicator.
7. Paste three or more failed-login log lines into Log Analyzer.
8. Open File Integrity and submit sample text.
9. Submit the same filename with modified content and compare SHA-256 hashes.
10. Open Network Lab and calculate `192.168.10.0/24`.
11. Export the event register as a CSV file.
12. Review the Audit Trail.
13. Log in with an Admin account and explore the Admin Panel.
14. Test user activation, deactivation and role management using appropriate test accounts.

## Project Structure

```text
CyberSentinel_SOC/
│
├── app.py
├── requirements.txt
├── README.md
│
├── data/
│   └── cybersentinel.db
│
├── logs/
│
├── monitored_files/
│
├── static/
│   ├── css/
│   │   └── style.css
│   │
│   └── js/
│       ├── app.js
│       └── dashboard.js
│
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── events.html
    ├── incidents.html
    ├── threat_intel.html
    ├── log_analyzer.html
    ├── file_integrity.html
    ├── network_lab.html
    ├── reports.html
    ├── audit.html
    ├── admin.html
    └── error.html
```

*Note: The structure above represents the main project files. Your local project may contain additional files.*

## Safety and Limitations

- This is an educational portfolio application, not a production SIEM.
- Threat Intelligence uses offline demonstration data, not a live reputation service.
- The Log Analyzer uses rule-based pattern matching, not a trained machine-learning model.
- File Integrity checks text submitted through the application; it does not continuously monitor the computer.
- Network Lab performs CIDR calculations only. It does not scan, probe or send network packets.
- Use only logs, files and networks you own or are authorized to test.
- Do not expose the Flask development server publicly.
- Production deployment requires HTTPS, secure secret management, a production WSGI server, automated tests and additional security review.

## Future Enhancements

- Real-time log ingestion.
- Advanced security event correlation.
- Integration with threat intelligence APIs.
- Network traffic analysis.
- Email alerts for critical incidents.
- Advanced reporting and analytics.
- Automated security testing.

## Portfolio Description

**CyberSentinel SOC — Security Operations Center Dashboard**

Developed a Flask-based SOC simulation featuring security event monitoring, incident lifecycle management, offline threat indicator lookup, log pattern analysis, SHA-256 integrity baselining, subnet calculations, audit logging and CSV reporting.

Implemented SQLite-backed authentication, CSRF protection, login rate limiting, session timeout and role-based Admin/Analyst access with user management.

## Author

**Gaurav Patil**

BSc Computer Science Graduate

Areas of Interest:
- Cybersecurity
- Security Operations Center (SOC)
- Networking
- Python Development
- System and Network Support

---

**Project:** CyberSentinel SOC  
**Type:** Educational Cybersecurity Portfolio Project  
**Backend:** Python + Flask  
**Database:** SQLite
