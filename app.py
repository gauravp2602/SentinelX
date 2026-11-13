from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, render_template_string
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path
from flask_wtf.csrf import CSRFProtect
import secrets
import time
import sqlite3
import csv
import io
import os
import re
import hashlib
import ipaddress

# ---------------------------------------------------------
# Paths and application configuration
# ---------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.environ.get(
        "DATABASE_PATH",
        str(APP_DIR / "data" / "cybersentinel.db")
    )
)
LOG_DIR = APP_DIR / "logs"
MONITOR_DIR = APP_DIR / "monitored_files"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
MONITOR_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

# Configure a stable SECRET_KEY in the Windows environment.
# The fallback is for local development only; sessions reset on restart.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY environment variable is required.")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

csrf = CSRFProtect(app)


# ---------------------------------------------------------
# Database helpers and initialization
# ---------------------------------------------------------

def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as con:

        # Create all database tables
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Analyst',
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
        );

        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            assigned_to TEXT
        );

        CREATE TABLE IF NOT EXISTS file_hashes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filepath TEXT UNIQUE NOT NULL,
            sha256 TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            state TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts(
            ip_address TEXT PRIMARY KEY,
            failed_count INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS login_activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            user_agent TEXT
        );

        CREATE TABLE IF NOT EXISTS password_reset_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS app_settings(
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        );
        """)

        # Migrate old users table if is_active column is missing
        user_columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(users)").fetchall()
        }

        if "is_active" not in user_columns:
            con.execute("""
                ALTER TABLE users
                ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
            """)

        # Project-owner admin bootstrap. Set ADMIN_PASSWORD temporarily in
        # the hosting environment for the first setup or one-time reset.
        # The one-time flag prevents the password being reset on every restart.
        owner = con.execute(
            "SELECT id FROM users WHERE LOWER(username) = 'gaurav'"
        ).fetchone()
        reset_done = con.execute(
            "SELECT setting_value FROM app_settings WHERE setting_key = 'owner_password_bootstrap_done'"
        ).fetchone()
        bootstrap_password = os.environ.get("ADMIN_PASSWORD")
        if bootstrap_password and len(bootstrap_password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters.")

        if not owner and bootstrap_password:
            con.execute(
                """INSERT INTO users(username, password_hash, role, created_at, is_active)
                   VALUES (?, ?, 'Admin', ?, 1)""",
                ("gaurav", generate_password_hash(bootstrap_password),
                 datetime.now().isoformat(timespec="seconds"))
            )
            con.execute(
                "INSERT OR REPLACE INTO app_settings(setting_key, setting_value) VALUES ('owner_password_bootstrap_done', '1')"
            )
        elif owner:
            # Always enforce the owner role; never expose role selection at registration.
            con.execute("UPDATE users SET role='Admin', is_active=1 WHERE id=?", (owner["id"],))
            if bootstrap_password and not reset_done:
                con.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (generate_password_hash(bootstrap_password), owner["id"])
                )
                con.execute(
                    "INSERT OR REPLACE INTO app_settings(setting_key, setting_value) VALUES ('owner_password_bootstrap_done', '1')"
                )

        # Ensure the project owner is the only Admin account. Other accounts
        # remain Analysts; an admin may later promote users from the protected panel.
        con.execute("UPDATE users SET role='Analyst' WHERE LOWER(username) != 'gaurav'")

        # Add sample events only when events table is empty
        if not con.execute("SELECT id FROM events LIMIT 1").fetchone():
            now = datetime.now()

            samples = [
                ("192.0.2.45", "Failed Login", "High",
                 "Multiple failed login attempts for demo-user"),
                ("198.51.100.23", "Port Scan", "Medium",
                 "Sequential connection attempts observed in lab telemetry"),
                ("203.0.113.77", "Malware Indicator", "Critical",
                 "Known-bad indicator in local demonstration feed"),
                ("10.0.0.15", "Policy Violation", "Low",
                 "Unusual outbound DNS query in sample log"),
                ("192.0.2.88", "Successful Login", "Info",
                 "Successful authentication from lab workstation"),
                ("198.51.100.54", "Failed Login", "High",
                 "Repeated authentication failures detected"),
            ]

            for i, item in enumerate(samples):
                con.execute(
                    """
                    INSERT INTO events(
                        timestamp, source_ip, event_type,
                        severity, message, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (now - timedelta(minutes=12 * i)).isoformat(
                            timespec="seconds"
                        ),
                        *item,
                        "Open"
                    )
                )

        # Add sample incident only when incidents table is empty
        if not con.execute("SELECT id FROM incidents LIMIT 1").fetchone():
            con.execute(
                """
                INSERT INTO incidents(
                    title, severity, source_ip, description,
                    status, created_at, assigned_to
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Repeated authentication failures",
                    "High",
                    "192.0.2.45",
                    "Investigate repeated failed logins in the sample dataset.",
                    "Open",
                    datetime.now().isoformat(timespec="seconds"),
                    "admin"
                )
            )



# ---------------------------------------------------------
# AUTHENTICATION AND AUDIT HELPERS
# ---------------------------------------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def audit(action):
    username = session.get("username")
    if username:
        with db() as con:
            con.execute(
                """
                INSERT INTO audit(username, action, timestamp)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    str(action)[:500],
                    datetime.now().isoformat(timespec="seconds")
                )
            )


def record_login_activity(username, status):
    """Store login metadata only; never store submitted passwords."""
    with db() as con:
        con.execute(
            """INSERT INTO login_activity(username, ip_address, status, attempted_at, user_agent)
               VALUES (?, ?, ?, ?, ?)""",
            (
                (username or "unknown")[:80],
                request.remote_addr or "unknown",
                status,
                datetime.now().isoformat(timespec="seconds"),
                request.headers.get("User-Agent", "")[:300]
            )
        )


# ADMIN ACCESS PROTECTION
def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):

        with db() as con:
            user = con.execute(
                """
                SELECT role, is_active
                FROM users
                WHERE username = ?
                """,
                (session["username"],)
            ).fetchone()

        if not user or not user["is_active"]:
            session.clear()
            flash("Your account is inactive.", "danger")
            return redirect(url_for("login"))

        if user["role"].lower() != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))

        return fn(*args, **kwargs)

    return wrapper


def get_stats():
    with db() as con:

        rows = con.execute(
            """
            SELECT severity, COUNT(*) AS n
            FROM events
            GROUP BY severity
            """
        ).fetchall()

        severity_counts = {
            row["severity"]: row["n"] for row in rows
        }

        total = con.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        open_incidents = con.execute(
            "SELECT COUNT(*) FROM incidents WHERE status='Open'"
        ).fetchone()[0]

        critical = con.execute(
            "SELECT COUNT(*) FROM events WHERE severity='Critical'"
        ).fetchone()[0]

        return {
            "total": total,
            "open_incidents": open_incidents,
            "critical": critical,
            "high": severity_counts.get("High", 0),
            "medium": severity_counts.get("Medium", 0),
            "low": severity_counts.get("Low", 0),
            "info": severity_counts.get("Info", 0)
        }


# ---------------------------------------------------------
# HOME AND AUTHENTICATION ROUTES
# ---------------------------------------------------------

@app.route("/")
def home():

    if session.get("username"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    ip = request.remote_addr or "unknown"
    now = time.time()
    lock_remaining = 0

    with db() as con:

        attempt = con.execute(
            """
            SELECT failed_count, locked_until
            FROM login_attempts
            WHERE ip_address = ?
            """,
            (ip,)
        ).fetchone()

        failed_count = attempt["failed_count"] if attempt else 0
        locked_until = attempt["locked_until"] if attempt else 0

        if locked_until > now:
            lock_remaining = int(locked_until - now) + 1

        if request.method == "POST":

            if lock_remaining > 0:

                flash(
                    "Login temporarily locked. Please wait.",
                    "danger"
                )

                return render_template(
                    "login.html",
                    lock_remaining=lock_remaining
                )

            username = request.form.get(
                "username", ""
            ).strip()

            password = request.form.get("password", "")

            user = con.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

            # CHECK USER CREDENTIALS
            if user and check_password_hash(
                user["password_hash"], password
            ):

                # CHECK ACCOUNT STATUS
                if not user["is_active"]:
                    record_login_activity(username, "Blocked - inactive account")

                    con.execute(
                        """
                        INSERT INTO audit(
                            username, action, timestamp
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            username,
                            f"Inactive account login blocked from IP {ip}",
                            datetime.now().isoformat(timespec="seconds")
                        )
                    )

                    flash(
                        "Your account is inactive. Contact administrator.",
                        "danger"
                    )

                    return render_template(
                        "login.html",
                        lock_remaining=0
                    )

                # SUCCESSFUL LOGIN
                record_login_activity(user["username"], "Successful")
                con.execute(
                    """
                    DELETE FROM login_attempts
                    WHERE ip_address = ?
                    """,
                    (ip,)
                )

                con.execute(
                    """
                    INSERT INTO audit(
                        username, action, timestamp
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        user["username"],
                        f"Successful login from IP {ip}",
                        datetime.now().isoformat(timespec="seconds")
                    )
                )

                session.clear()
                session.permanent = True
                session["username"] = user["username"]
                session["role"] = user["role"]

                return redirect(url_for("dashboard"))

            # FAILED LOGIN ATTEMPT
            record_login_activity(username or "unknown", "Failed")
            if locked_until and now >= locked_until:
                failed_count = 0

            failed_count += 1

            con.execute(
                """
                INSERT INTO audit(
                    username, action, timestamp
                )
                VALUES (?, ?, ?)
                """,
                (
                    username[:80] or "unknown",
                    f"Failed login attempt from IP {ip}",
                    datetime.now().isoformat(timespec="seconds")
                )
            )

            lock_until = 0

            if failed_count >= 5:

                lock_until = now + 300
                lock_remaining = 300
                failed_count = 0

                con.execute(
                    """
                    INSERT INTO audit(
                        username, action, timestamp
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        username[:80] or "unknown",
                        f"Login locked for 5 minutes from IP {ip}",
                        datetime.now().isoformat(timespec="seconds")
                    )
                )

                flash(
                    "5 failed attempts. Login locked for 5 minutes.",
                    "danger"
                )

            else:

                flash(
                    "Invalid username or password.",
                    "danger"
                )

            # SAVE LOGIN ATTEMPTS
            con.execute(
                """
                INSERT INTO login_attempts(
                    ip_address, failed_count, locked_until
                )
                VALUES (?, ?, ?)

                ON CONFLICT(ip_address) DO UPDATE SET
                    failed_count = excluded.failed_count,
                    locked_until = excluded.locked_until
                """,
                (ip, failed_count, lock_until)
            )

    return render_template(
        "login.html",
        lock_remaining=lock_remaining
    )

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3 or len(username) > 80:
            flash(
                "Username must be between 3 and 80 characters.",
                "danger"
            )
        elif username.lower() == "gaurav":
            flash("This username is reserved for the project administrator.", "danger")
        elif len(password) < 6:
            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )
        elif password != confirm_password:
            flash(
                "Passwords do not match. Please try again.",
                "danger"
            )
        else:
            try:
                with db() as con:
                    con.execute(
                        """
                        INSERT INTO users(
                            username, password_hash, role, created_at
                        ) VALUES (?, ?, ?, ?)
                        """,
                        (
                            username,
                            generate_password_hash(password),
                            "Analyst",
                            datetime.now().isoformat(timespec="seconds")
                        )
                    )

                    con.execute(
                        """
                        INSERT INTO audit(username, action, timestamp)
                        VALUES (?, ?, ?)
                        """,
                        (
                            username,
                            "Account registered",
                            datetime.now().isoformat(timespec="seconds")
                        )
                    )

                flash("Account created successfully. Please log in.", "success")
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                flash("That username already exists. Choose another.", "danger")

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        generic_message = "If that account exists, a reset link has been generated."
        with db() as con:
            user = con.execute(
                "SELECT id, username FROM users WHERE LOWER(username)=LOWER(?) AND is_active=1",
                (username,)
            ).fetchone()
            if user:
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                expires = time.time() + 20 * 60
                con.execute(
                    "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)",
                    (user["id"], token_hash, expires,
                     datetime.now().isoformat(timespec="seconds"))
                )
                reset_url = url_for("reset_password", token=raw_token, _external=True)
                # Demo mode: print the one-time link to the server console.
                # Configure email delivery before using this flow in production.
                app.logger.warning("DEMO PASSWORD RESET LINK for %s: %s", user["username"], reset_url)
        flash(generic_message + " Check the application server console (demo mode).", "info")
        return redirect(url_for("forgot_password"))
    return render_template_string(
        """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Forgot Password | CyberSentinel SOC</title><style>body{font-family:Arial,sans-serif;background:#0b1220;color:#e8eefc;display:grid;place-items:center;min-height:100vh;margin:0}.card{background:#151f33;padding:30px;border-radius:14px;width:min(90%,380px);box-sizing:border-box}input,button{width:100%;padding:12px;margin-top:12px;border-radius:8px;border:1px solid #34445f;box-sizing:border-box}button{background:#36a3ff;color:#06111f;font-weight:bold;cursor:pointer}a{color:#69bdff}small{color:#aab8ce}</style></head><body><div class='card'><h2>Forgot password</h2><p>Enter your username to generate a one-time reset link.</p>{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<p>{{ message }}</p>{% endfor %}{% endwith %}<form method='post'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><input name='username' required minlength='3' placeholder='Username'><button type='submit'>Generate reset link</button></form><p><small>Demo mode: the link is printed in the application server console. Configure email delivery before production use.</small></p><a href='{{ url_for("login") }}'>Back to login</a></div></body></html>"""
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with db() as con:
        reset = con.execute(
            """SELECT id, user_id FROM password_reset_tokens
               WHERE token_hash=? AND used=0 AND expires_at>?""",
            (token_hash, time.time())
        ).fetchone()
    if not reset:
        flash("This password reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            with db() as con:
                con.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (generate_password_hash(password), reset["user_id"])
                )
                con.execute(
                    "UPDATE password_reset_tokens SET used=1 WHERE user_id=?",
                    (reset["user_id"],)
                )
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template_string(
        """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Reset Password | CyberSentinel SOC</title><style>body{font-family:Arial,sans-serif;background:#0b1220;color:#e8eefc;display:grid;place-items:center;min-height:100vh;margin:0}.card{background:#151f33;padding:30px;border-radius:14px;width:min(90%,380px);box-sizing:border-box}input,button{width:100%;padding:12px;margin-top:12px;border-radius:8px;border:1px solid #34445f;box-sizing:border-box}button{background:#36a3ff;color:#06111f;font-weight:bold;cursor:pointer}</style></head><body><div class='card'><h2>Set new password</h2>{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<p>{{ message }}</p>{% endfor %}{% endwith %}<form method='post'><input type='hidden' name='csrf_token' value='{{ csrf_token() }}'><input type='password' name='password' minlength='6' required placeholder='New password'><input type='password' name='confirm_password' minlength='6' required placeholder='Confirm new password'><button type='submit'>Update password</button></form></div></body></html>"""
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("Logged out")
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------
# ADMIN PANEL AND USER MANAGEMENT
# ---------------------------------------------------------

@app.route("/admin", methods=["GET"])
@admin_required
def admin_panel():

    with db() as con:

        users = con.execute(
            """
            SELECT id, username, role, is_active, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()

        total_users = con.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        active_users = con.execute(
            "SELECT COUNT(*) FROM users WHERE is_active = 1"
        ).fetchone()[0]

        inactive_users = con.execute(
            "SELECT COUNT(*) FROM users WHERE is_active = 0"
        ).fetchone()[0]

        admin_count = con.execute(
            """
            SELECT COUNT(*) FROM users
            WHERE LOWER(role) = 'admin' AND is_active = 1
            """
        ).fetchone()[0]

        login_activity = con.execute(
            "SELECT username, ip_address, status, attempted_at, user_agent "
            "FROM login_activity ORDER BY id DESC LIMIT 100"
        ).fetchall()

        successful_logins = con.execute(
            "SELECT COUNT(*) FROM login_activity WHERE status='Successful'"
        ).fetchone()[0]
        failed_logins = con.execute(
            "SELECT COUNT(*) FROM login_activity WHERE status='Failed'"
        ).fetchone()[0]

    return render_template(
        "admin.html",
        users=users,
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        admin_count=admin_count,
        login_activity=login_activity,
        successful_logins=successful_logins,
        failed_logins=failed_logins
    )


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user_status(user_id):

    with db() as con:

        target = con.execute(
            """
            SELECT id, username, role, is_active
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not target:
            flash("User not found.", "danger")

        elif target["username"] == session["username"]:
            flash("You cannot deactivate your own account.", "danger")

        elif target["is_active"] and target["role"].lower() == "admin":

            admin_count = con.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE LOWER(role) = 'admin' AND is_active = 1
                """
            ).fetchone()[0]

            if admin_count <= 1:
                flash("You cannot deactivate the last active admin.", "danger")
            else:
                con.execute(
                    "UPDATE users SET is_active = 0 WHERE id = ?",
                    (user_id,)
                )
                flash("User deactivated successfully.", "success")

        else:
            new_status = 0 if target["is_active"] else 1

            con.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (new_status, user_id)
            )

            flash(
                "User activated successfully." if new_status
                else "User deactivated successfully.",
                "success"
            )

    audit(f"Admin changed account status for user ID {user_id}")

    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):

    new_role = request.form.get("role", "").strip().title()

    if new_role not in ("Admin", "Analyst"):
        flash("Invalid user role.", "danger")
        return redirect(url_for("admin_panel"))

    with db() as con:

        target = con.execute(
            """
            SELECT id, username, role, is_active
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not target:
            flash("User not found.", "danger")

        elif target["username"] == session["username"]:
            flash("You cannot change your own role.", "danger")

        elif (
            target["role"].lower() == "admin"
            and target["is_active"]
            and new_role == "Analyst"
        ):

            admin_count = con.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE LOWER(role) = 'admin' AND is_active = 1
                """
            ).fetchone()[0]

            if admin_count <= 1:
                flash("You cannot demote the last active admin.", "danger")
            else:
                con.execute(
                    "UPDATE users SET role = ? WHERE id = ?",
                    (new_role, user_id)
                )
                flash("User role updated successfully.", "success")

        else:
            con.execute(
                "UPDATE users SET role = ? WHERE id = ?",
                (new_role, user_id)
            )
            flash("User role updated successfully.", "success")

    audit(f"Admin changed role for user ID {user_id} to {new_role}")

    return redirect(url_for("admin_panel"))

# ---------------------------------------------------------
# Dashboard and event routes
# ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        events = con.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 8"
        ).fetchall()
        incidents = con.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT 5"
        ).fetchall()

    return render_template(
        "dashboard.html",
        stats=get_stats(),
        events=events,
        incidents=incidents
    )


@app.route("/events")
@login_required
def events():
    severity = request.args.get("severity", "")

    with db() as con:
        if severity:
            rows = con.execute(
                "SELECT * FROM events WHERE severity=? ORDER BY id DESC",
                (severity,)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM events ORDER BY id DESC"
            ).fetchall()

    return render_template(
        "events.html",
        events=rows,
        selected=severity
    )


@app.route("/events/<int:event_id>/resolve", methods=["POST"])
@login_required
def resolve_event(event_id):
    with db() as con:
        con.execute(
            "UPDATE events SET status='Resolved' WHERE id=?",
            (event_id,)
        )

    audit(f"Resolved event #{event_id}")
    flash("Event marked as resolved.", "success")
    return redirect(request.referrer or url_for("events"))


# ---------------------------------------------------------
# Incident management routes
# ---------------------------------------------------------

@app.route("/incidents", methods=["GET", "POST"])
@login_required
def incidents():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "Medium")
        source_ip = request.form.get("source_ip", "").strip()
        description = request.form.get("description", "").strip()

        if title:
            with db() as con:
                con.execute(
                    """
                    INSERT INTO incidents(
                        title, severity, source_ip, description,
                        status, created_at, assigned_to
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        severity,
                        source_ip,
                        description,
                        "Open",
                        datetime.now().isoformat(timespec="seconds"),
                        session["username"]
                    )
                )

            audit("Created incident")
            flash("Incident created.", "success")

        return redirect(url_for("incidents"))

    with db() as con:
        rows = con.execute(
            "SELECT * FROM incidents ORDER BY id DESC"
        ).fetchall()

    return render_template("incidents.html", incidents=rows)


@app.route("/incidents/<int:incident_id>/status", methods=["POST"])
@login_required
def incident_status(incident_id):
    status = request.form.get("status", "Open")

    if status not in ["Open", "Investigating", "Closed"]:
        status = "Open"

    with db() as con:
        con.execute(
            "UPDATE incidents SET status=? WHERE id=?",
            (status, incident_id)
        )

    audit(f"Updated incident #{incident_id}")
    return redirect(url_for("incidents"))


# ---------------------------------------------------------
# Threat intelligence demonstration route
# ---------------------------------------------------------

@app.route("/threat-intel", methods=["GET", "POST"])
@login_required
def threat_intel():
    result = None

    if request.method == "POST":
        raw = request.form.get("ip", "").strip()

        try:
            ip = ipaddress.ip_address(raw)
            # Documentation/test ranges are harmless demo indicators only.
            demo_bad = {"203.0.113.77", "198.51.100.66"}

            result = {
                "ip": str(ip),
                "valid": True,
                "classification": (
                    "Demo malicious indicator"
                    if str(ip) in demo_bad
                    else (
                        "Private / lab address"
                        if ip.is_private
                        else "No local threat match"
                    )
                ),
                "risk": (
                    "High"
                    if str(ip) in demo_bad
                    else ("Informational" if ip.is_private else "Unknown")
                ),
                "note": (
                    "Offline demonstration lookup only. "
                    "This is not a live reputation feed."
                )
            }

        except ValueError:
            result = {
                "valid": False,
                "note": "Enter a valid IPv4 or IPv6 address."
            }

        audit("Performed offline IP indicator lookup")

    return render_template("threat_intel.html", result=result)


# ---------------------------------------------------------
# Log analyzer route
# ---------------------------------------------------------

@app.route("/log-analyzer", methods=["GET", "POST"])
@login_required
def log_analyzer():
    report = None

    if request.method == "POST":
        content = request.form.get("log_text", "")
        lines = [line for line in content.splitlines() if line.strip()]

        failed = sum(
            1 for line in lines
            if re.search(
                r"failed|failure|invalid password|authentication error",
                line,
                re.I
            )
        )
        denied = sum(
            1 for line in lines
            if re.search(r"denied|blocked|unauthorized", line, re.I)
        )
        errors = sum(
            1 for line in lines
            if re.search(r"error|critical|fatal", line, re.I)
        )
        ips = sorted(set(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            content
        )))

        report = {
            "lines": len(lines),
            "failed": failed,
            "denied": denied,
            "errors": errors,
            "ips": ips
        }

        # Add a synthetic event summary when suspicious lines are found.
        if failed >= 3:
            with db() as con:
                con.execute(
                    """
                    INSERT INTO events(
                        timestamp, source_ip, event_type,
                        severity, message, status
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.now().isoformat(timespec="seconds"),
                        ips[0] if ips else "Unknown",
                        "Log Anomaly",
                        "High",
                        f"Log analysis found {failed} failed-authentication messages.",
                        "Open"
                    )
                )

        audit("Analyzed pasted log data")

    return render_template("log_analyzer.html", report=report)


# ---------------------------------------------------------
# File integrity demonstration route
# ---------------------------------------------------------

@app.route("/file-integrity", methods=["GET", "POST"])
@login_required
def file_integrity():
    message = None

    if request.method == "POST":
        name = request.form.get("filename", "").strip()
        content = request.form.get("content", "")

        if (
            not name
            or "/" in name
            or "\\" in name
            or name in [".", ".."]
        ):
            message = (
                "Use a simple filename only (no folders or paths).",
                "danger"
            )
        else:
            target = MONITOR_DIR / name
            target.write_text(content, encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()

            with db() as con:
                old = con.execute(
                    "SELECT sha256 FROM file_hashes WHERE filepath=?",
                    (name,)
                ).fetchone()

                state = (
                    "New baseline"
                    if not old
                    else ("Unchanged" if old["sha256"] == digest else "Modified")
                )

                con.execute(
                    """
                    INSERT INTO file_hashes(filepath, sha256, checked_at, state)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(filepath) DO UPDATE SET
                        sha256=excluded.sha256,
                        checked_at=excluded.checked_at,
                        state=excluded.state
                    """,
                    (
                        name,
                        digest,
                        datetime.now().isoformat(timespec="seconds"),
                        state
                    )
                )

            audit(f"Updated integrity baseline for {name}")
            message = (
                f"{name}: {state}. SHA-256: {digest}",
                "success"
            )

    with db() as con:
        rows = con.execute(
            "SELECT * FROM file_hashes ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "file_integrity.html",
        hashes=rows,
        message=message
    )


# ---------------------------------------------------------
# Safe private-network subnet calculator
# ---------------------------------------------------------

@app.route("/network-lab", methods=["GET", "POST"])
@login_required
def network_lab():
    result = None

    if request.method == "POST":
        raw = request.form.get("network", "").strip()

        try:
            net = ipaddress.ip_network(raw, strict=False)

            if not (net.is_private or net.is_loopback):
                result = {
                    "error": (
                        "For safety, this lab tool accepts private "
                        "or loopback networks only."
                    )
                }
            elif net.num_addresses > 256:
                result = {
                    "error": (
                        "Network too large. Use a lab subnet "
                        "with 256 addresses or fewer."
                    )
                }
            else:
                hosts = list(net.hosts())
                result = {
                    "network": str(net),
                    "hosts": net.num_addresses,
                    "usable": max(net.num_addresses - 2, 0),
                    "first": str(hosts[0]) if hosts else "N/A",
                    "last": str(hosts[-1]) if hosts else "N/A",
                    "note": (
                        "Subnet calculator only. "
                        "It does not scan or send packets."
                    )
                }

            audit("Used private network lab calculator")

        except ValueError:
            result = {
                "error": (
                    "Enter a valid CIDR network, "
                    "for example 192.168.1.0/24."
                )
            }

    return render_template("network_lab.html", result=result)


# ---------------------------------------------------------
# API, reports and audit routes
# ---------------------------------------------------------

@app.route("/api/overview")
@login_required
def api_overview():
    with db() as con:
        rows = con.execute(
            "SELECT severity, COUNT(*) AS n FROM events GROUP BY severity"
        ).fetchall()
        recent = con.execute(
            """
            SELECT timestamp, event_type, severity
            FROM events ORDER BY id DESC LIMIT 7
            """
        ).fetchall()

    return jsonify({
        "severity": {row["severity"]: row["n"] for row in rows},
        "recent": [dict(row) for row in recent]
    })


@app.route("/reports")
@login_required
def reports():
    with db() as con:
        events_count = con.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        incidents_count = con.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]
        open_count = con.execute(
            "SELECT COUNT(*) FROM incidents WHERE status!='Closed'"
        ).fetchone()[0]

    return render_template(
        "reports.html",
        stats={
            "events": events_count,
            "incidents": incidents_count,
            "open": open_count
        }
    )


@app.route("/reports/export")
@login_required
def export_report():
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Timestamp", "Source IP", "Event Type",
        "Severity", "Message", "Status"
    ])

    with db() as con:
        rows = con.execute(
            "SELECT * FROM events ORDER BY id DESC"
        ).fetchall()

    for row in rows:
        writer.writerow([
            row["id"],
            row["timestamp"],
            row["source_ip"],
            row["event_type"],
            row["severity"],
            row["message"],
            row["status"]
        ])

    memory_file = io.BytesIO(output.getvalue().encode("utf-8"))
    memory_file.seek(0)

    audit("Exported CSV event report")

    return send_file(
        memory_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name="cybersentinel_events.csv"
    )


@app.route("/audit")
@login_required
def audit_logs():
    with db() as con:
        rows = con.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT 100"
        ).fetchall()

    return render_template("audit.html", logs=rows)


# ---------------------------------------------------------
# Error handlers and application start
# ---------------------------------------------------------

@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "error.html",
        code=404,
        message="Page not found"
    ), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template(
        "error.html",
        code=500,
        message="Unexpected server error"
    ), 500


init_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
