# Contributing to CyberSentinel SOC

Thank you for your interest in contributing to CyberSentinel SOC!

CyberSentinel SOC is an educational Security Operations Center (SOC) dashboard built using Python, Flask, SQLite, HTML, CSS, and JavaScript.

Contributions, bug reports, suggestions, and improvements are welcome.

## 1. Getting Started

Before contributing, make sure you have:

- Python 3.10 or later
- Git
- Visual Studio Code or another code editor
- Basic knowledge of Python and Flask

## 2. Setup the Project

Clone the repository:

```bash
git clone -b cybersentinel-soc https://github.com/gauravp2602/SentinelX.git
```

Navigate to the project folder and create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open the application at:

http://127.0.0.1:5000

## 3. How to Contribute

1. Fork the repository.
2. Create a new branch for your changes.
3. Make your changes.
4. Test the application.
5. Commit your changes with a clear message.
6. Submit a Pull Request.

Example branch:

```bash
git switch -c feature/your-feature-name
```

Example commit:

```bash
git commit -m "Improve dashboard layout"
```

## 4. Contribution Guidelines

Please follow these guidelines:

- Keep code readable and organized.
- Use meaningful variable and function names.
- Avoid unnecessary changes to existing features.
- Test changes before submitting them.
- Update documentation when functionality changes.
- Do not commit passwords, API keys, database files, or other secrets.
- Do not include real sensitive logs or personal information.

## 5. Reporting Bugs

When reporting a bug, include:

- A clear description of the issue.
- Steps to reproduce it.
- Expected behavior.
- Actual behavior.
- Error messages or screenshots, if available.

Never include passwords, tokens, or confidential information in bug reports.

## 6. Feature Suggestions

Feature suggestions are welcome.

Please explain:
- What feature you want to add.
- Why it would be useful.
- How it could improve the SOC dashboard.

## 7. Security Issues

For security-related issues, please follow the instructions in [SECURITY.md](SECURITY.md).

## 8. License and Usage

Check the repository's license before redistributing or reusing the project.

---

Thank you for helping improve CyberSentinel SOC!

**Project:** CyberSentinel SOC  
**Maintainer:** Gaurav Patil  
**Purpose:** Cybersecurity Learning and SOC Demonstration