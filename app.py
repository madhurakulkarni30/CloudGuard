import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "cloudguard.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
KEY_FILE = os.path.join(BASE_DIR, "secret.key")
MAX_FAILED_ATTEMPTS = 5
BLOCK_MINUTES = 5

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
os.makedirs(STORAGE_DIR, exist_ok=True)

def get_fernet():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return Fernet(f.read())

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        blocked_until TEXT
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        event TEXT NOT NULL,
        ip TEXT,
        timestamp TEXT NOT NULL
    );
    """)
    # Demo accounts
    for username, password, role in [
        ("admin", "admin123", "admin"),
        ("student", "student123", "user")
    ]:
        try:
            conn.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                (username, hash_password(password), role)
            )
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

def log_event(username, event):
    conn = db()
    conn.execute(
        "INSERT INTO audit_logs(username,event,ip,timestamp) VALUES(?,?,?,?)",
        (username, event, request.remote_addr or "unknown",
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            log_event(session.get("username", "unknown"),
                      "UNAUTHORIZED ADMIN ACCESS BLOCKED")
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if user and user["blocked_until"]:
            try:
                blocked_until = datetime.fromisoformat(user["blocked_until"])
                if datetime.now() < blocked_until:
                    log_event(username, "LOGIN BLOCKED - USER TEMPORARILY BLOCKED")
                    conn.close()
                    flash("Account temporarily blocked due to repeated failures.", "danger")
                    return render_template("login.html")
                conn.execute(
                    "UPDATE users SET failed_attempts=0, blocked_until=NULL WHERE id=?",
                    (user["id"],)
                )
                conn.commit()
                user = conn.execute(
                    "SELECT * FROM users WHERE id=?", (user["id"],)
                ).fetchone()
            except ValueError:
                pass

        if not user:
            log_event(username or "unknown", "LOGIN FAILED - UNKNOWN USER")
            conn.close()
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        if hash_password(password) != user["password_hash"]:
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                until = datetime.now() + timedelta(minutes=BLOCK_MINUTES)
                conn.execute(
                    "UPDATE users SET failed_attempts=?, blocked_until=? WHERE id=?",
                    (attempts, until.isoformat(), user["id"])
                )
                conn.commit()
                log_event(username, "INTRUSION DETECTED - ACCOUNT BLOCKED")
                conn.close()
                flash("🚨 Suspicious activity detected. Account blocked for 5 minutes.", "danger")
                return render_template("login.html")
            conn.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?",
                (attempts, user["id"])
            )
            conn.commit()
            log_event(username, f"LOGIN FAILED - ATTEMPT {attempts}")
            conn.close()
            flash(f"Invalid password. Failed attempt {attempts}/{MAX_FAILED_ATTEMPTS}.", "danger")
            return render_template("login.html")

        conn.execute(
            "UPDATE users SET failed_attempts=0, blocked_until=NULL WHERE id=?",
            (user["id"],)
        )
        conn.commit()
        conn.close()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        log_event(username, "LOGIN SUCCESS")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    if "user_id" in session:
        log_event(username, "LOGOUT")
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn = db()
    total_files = conn.execute("SELECT COUNT(*) c FROM files").fetchone()["c"]
    total_logs = conn.execute("SELECT COUNT(*) c FROM audit_logs").fetchone()["c"]
    failed = conn.execute(
        "SELECT COUNT(*) c FROM audit_logs WHERE event LIKE 'LOGIN FAILED%'"
    ).fetchone()["c"]
    blocked = conn.execute(
        "SELECT COUNT(*) c FROM audit_logs WHERE event LIKE '%BLOCKED%'"
    ).fetchone()["c"]
    recent = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8"
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        total_files=total_files, total_logs=total_logs,
        failed=failed, blocked=blocked, recent=recent
    )

@app.route("/files")
@login_required
def files_page():
    conn = db()
    if session["role"] == "admin":
        rows = conn.execute("""
            SELECT files.*, users.username
            FROM files JOIN users ON files.owner_id=users.id
            ORDER BY files.id DESC
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT files.*, users.username
            FROM files JOIN users ON files.owner_id=users.id
            WHERE owner_id=? ORDER BY files.id DESC
        """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("files.html", files=rows)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file first.", "warning")
        return redirect(url_for("files_page"))

    original = secure_filename(file.filename)
    if not original:
        flash("Invalid filename.", "danger")
        return redirect(url_for("files_page"))

    raw = file.read()
    token = get_fernet().encrypt(raw)
    stored = secrets.token_hex(16) + ".enc"

    with open(os.path.join(STORAGE_DIR, stored), "wb") as f:
        f.write(token)

    conn = db()
    conn.execute(
        "INSERT INTO files(original_name,stored_name,owner_id,uploaded_at) VALUES(?,?,?,?)",
        (original, stored, session["user_id"],
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    log_event(session["username"], f"FILE ENCRYPTED AND STORED: {original}")
    flash(f"'{original}' encrypted and stored successfully.", "success")
    return redirect(url_for("files_page"))

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    conn = db()
    row = conn.execute("""
        SELECT * FROM files WHERE id=?
    """, (file_id,)).fetchone()
    conn.close()

    if not row:
        abort(404)
    if session["role"] != "admin" and row["owner_id"] != session["user_id"]:
        log_event(session["username"], "UNAUTHORIZED FILE ACCESS BLOCKED")
        flash("Access denied.", "danger")
        return redirect(url_for("files_page"))

    path = os.path.join(STORAGE_DIR, row["stored_name"])
    if not os.path.exists(path):
        abort(404)

    try:
        with open(path, "rb") as f:
            decrypted = get_fernet().decrypt(f.read())
    except Exception:
        log_event(session["username"], "FILE DECRYPTION ERROR")
        abort(500)

    out = os.path.join(STORAGE_DIR, "download_" + row["original_name"])
    with open(out, "wb") as f:
        f.write(decrypted)
    log_event(session["username"], f"FILE DECRYPTED/DOWNLOADED: {row['original_name']}")
    return send_file(out, as_attachment=True, download_name=row["original_name"])

@app.route("/logs")
@login_required
@admin_required
def logs():
    conn = db()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("logs.html", logs=rows)

@app.route("/attack-simulator", methods=["GET", "POST"])
@login_required
@admin_required
def attack_simulator():
    result = None
    if request.method == "POST":
        target = request.form.get("target", "student").strip()
        count = min(max(int(request.form.get("count", 5)), 1), 20)
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (target,)
        ).fetchone()
        if not user:
            conn.close()
            flash("Target user does not exist.", "danger")
            return redirect(url_for("attack_simulator"))

        attempts = user["failed_attempts"]
        for i in range(count):
            attempts += 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                until = datetime.now() + timedelta(minutes=BLOCK_MINUTES)
                conn.execute(
                    "UPDATE users SET failed_attempts=?, blocked_until=? WHERE id=?",
                    (attempts, until.isoformat(), user["id"])
                )
                log_event(target, "SIMULATED ATTACK - ACCOUNT BLOCKED")
                break
            conn.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?",
                (attempts, user["id"])
            )
            log_event(target, f"SIMULATED ATTACK - FAILED LOGIN {attempts}")
        conn.commit()
        conn.close()
        result = f"{count} simulated attempts generated for '{target}'."
    return render_template("attack.html", result=result)

@app.route("/reset-demo", methods=["POST"])
@login_required
@admin_required
def reset_demo():
    conn = db()
    conn.execute("UPDATE users SET failed_attempts=0, blocked_until=NULL")
    conn.commit()
    conn.close()
    log_event(session["username"], "DEMO SECURITY STATE RESET")
    flash("Demo security state reset.", "success")
    return redirect(url_for("dashboard"))

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum size is 10 MB.", "danger")
    return redirect(url_for("files_page"))

if __name__ == "__main__":
    init_db()
    print("\nCloudGuard running at http://127.0.0.1:5000")
    print("Admin:   admin / admin123")
    print("Student: student / student123\n")
    app.run(debug=True)
