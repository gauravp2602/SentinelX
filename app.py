import os, re, json, socket, ssl, hashlib, ipaddress, secrets
from datetime import datetime, timezone
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from modules.security_tools import (
    password_audit, analyze_url, dns_lookup, ssl_inspect,
    scan_private_host, analyze_log_text, hash_text
)

app = Flask(__name__)
app.config.from_object(Config)

def db():
    import sqlite3
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

def log_event(event_type, details):
    user_id = session.get("user_id")
    with db() as conn:
        conn.execute(
            "INSERT INTO events(user_id,event_type,details,created_at) VALUES(?,?,?,?)",
            (user_id, event_type, str(details)[:1000], datetime.now(timezone.utc).isoformat())
        )
        conn.commit()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_globals():
    return {"current_user": session.get("username")}

@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters (letters, numbers, _, ., -).", "danger")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "danger")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "danger")
        else:
            try:
                with db() as conn:
                    conn.execute(
                        "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                        (username, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat())
                    )
                    conn.commit()
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("login"))
            except Exception:
                flash("That username or email may already be registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? OR email=?",
                (identity, identity.lower())
            ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            log_event("login", "Successful login")
            return redirect(url_for("dashboard"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event("logout", "User signed out")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) n FROM events WHERE user_id=?", (session["user_id"],)).fetchone()["n"]
        recent = conn.execute(
            "SELECT event_type,details,created_at FROM events WHERE user_id=? ORDER BY id DESC LIMIT 7",
            (session["user_id"],)
        ).fetchall()
    return render_template("dashboard.html", event_count=total, recent=recent)

@app.route("/password-audit", methods=["GET", "POST"])
@login_required
def password_page():
    result = None
    if request.method == "POST":
        result = password_audit(request.form.get("password", ""))
        log_event("password_audit", "Password strength audit performed; password itself not stored")
    return render_template("tool.html", title="Password Security Audit", description="Evaluate password length and common composition risks. Your entered password is not saved.", result=result, tool="password")

@app.route("/hash-generator", methods=["GET", "POST"])
@login_required
def hash_page():
    result = None
    if request.method == "POST":
        text_value = request.form.get("text", "")
        result = hash_text(text_value)
        log_event("hash_generated", "Generated SHA-256 and SHA-512 hashes")
    return render_template("tool.html", title="Hash Generator", description="Generate SHA-256 and SHA-512 digests from text.", result=result, tool="hash")

@app.route("/url-analyzer", methods=["GET", "POST"])
@login_required
def url_page():
    result = None
    if request.method == "POST":
        result = analyze_url(request.form.get("url", ""))
        log_event("url_analysis", "Analyzed URL indicators")
    return render_template("tool.html", title="Phishing URL Analyzer", description="Heuristic checks only; this is not a definitive phishing verdict.", result=result, tool="url")

@app.route("/dns-analyzer", methods=["GET", "POST"])
@login_required
def dns_page():
    result = None
    if request.method == "POST":
        result = dns_lookup(request.form.get("domain", ""))
        log_event("dns_lookup", "DNS lookup performed")
    return render_template("tool.html", title="DNS Analyzer", description="Resolve A, AAAA, MX and NS records using the system resolver.", result=result, tool="dns")

@app.route("/ssl-checker", methods=["GET", "POST"])
@login_required
def ssl_page():
    result = None
    if request.method == "POST":
        result = ssl_inspect(request.form.get("hostname", ""))
        log_event("ssl_inspection", "TLS certificate inspection performed")
    return render_template("tool.html", title="TLS / SSL Certificate Checker", description="Inspect the certificate presented by a hostname on TCP port 443.", result=result, tool="ssl")

@app.route("/network-check", methods=["GET", "POST"])
@login_required
def network_page():
    result = None
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        ports = request.form.get("ports", "22,80,443")
        consent = request.form.get("authorized") == "yes"
        result = scan_private_host(host, ports, consent)
        log_event("network_check", f"Private-network TCP check requested for {host}")
    return render_template("tool.html", title="Authorized Private Network Check", description="Checks a small list of TCP ports on a private IP address only. Use only on devices/networks you own or are authorized to test.", result=result, tool="network")

@app.route("/log-analyzer", methods=["GET", "POST"])
@login_required
def log_page():
    result = None
    if request.method == "POST":
        result = analyze_log_text(request.form.get("logs", ""))
        log_event("log_analysis", "Security log text analyzed")
    return render_template("tool.html", title="Security Log Analyzer", description="Paste a small log excerpt to identify common failed-login and error indicators. Logs are not retained.", result=result, tool="logs")

@app.route("/activity")
@login_required
def activity():
    with db() as conn:
        rows = conn.execute(
            "SELECT event_type,details,created_at FROM events WHERE user_id=? ORDER BY id DESC LIMIT 100",
            (session["user_id"],)
        ).fetchall()
    return render_template("activity.html", rows=rows)

@app.errorhandler(404)
def not_found(_):
    return render_template("message.html", title="Page not found", message="The requested page does not exist."), 404

@app.errorhandler(500)
def server_error(_):
    return render_template("message.html", title="Something went wrong", message="An internal error occurred. Check the terminal for details."), 500

if __name__ == "__main__":
    init_db()
    print("SentinelX starting at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
