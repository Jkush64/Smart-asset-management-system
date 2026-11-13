import sqlite3
import csv
import io
import math
import os
import secrets
import tempfile
from contextlib import closing
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, abort, after_this_request, flash, redirect, render_template, request, session, url_for, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
secret_key = os.environ.get("SAMS_SECRET_KEY")
is_production = os.environ.get("SAMS_ENV", "").lower() == "production"
if is_production and not secret_key:
    raise RuntimeError("SAMS_SECRET_KEY must be set when SAMS_ENV=production.")
app.secret_key = secret_key or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
)
DB_FILE = os.path.join(app.root_path, "assets.db")
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def database_connection():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn

def query_scalar(query, args=()):
    """Return one database value, closing the connection even if the query fails."""
    conn = database_connection()
    try:
        row = conn.execute(query, args).fetchone()
        return row[0] if row is not None and row[0] is not None else 0
    finally:
        conn.close()

def query_rows(query, args=(), use_row_factory=True):
    """Return matching rows, closing the connection even if the query fails."""
    conn = database_connection()
    if not use_row_factory:
        conn.row_factory = None
    try:
        return conn.execute(query, args).fetchall()
    finally:
        conn.close()

def execute_commit(query, args=()):
    """Execute one write in a transaction and always close its connection."""
    conn = database_connection()
    try:
        with conn:
            conn.execute(query, args)
    finally:
        conn.close()

# INITIALIZE SYSTEM SCHEMA ON BOOT
conn = database_connection()
conn.execute("PRAGMA journal_mode = WAL")
conn.execute("CREATE TABLE IF NOT EXISTS branches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, address TEXT NOT NULL, manager_name TEXT NOT NULL, manager_email TEXT NOT NULL, manager_contact TEXT NOT NULL, max_assets INTEGER NOT NULL, status TEXT DEFAULT 'active')")
conn.execute("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, serial_no TEXT NOT NULL UNIQUE, model TEXT NOT NULL, category TEXT NOT NULL, location_room TEXT NOT NULL, purchased_date TEXT NOT NULL, cost REAL NOT NULL, status TEXT NOT NULL, branch_id INTEGER NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS maintenance (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_name TEXT NOT NULL, scheduled_date TEXT NOT NULL, priority TEXT NOT NULL, status TEXT NOT NULL, technician TEXT NOT NULL, est_cost REAL NOT NULL, asset_id INTEGER NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, username TEXT NOT NULL, asset_info TEXT NOT NULL, action_taken TEXT NOT NULL, log_level TEXT NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL, branch_assigned TEXT NOT NULL DEFAULT 'Unassigned', last_login TEXT NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
conn.execute("CREATE TABLE IF NOT EXISTS junk_assets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, serial_no TEXT NOT NULL UNIQUE, category TEXT NOT NULL, reason TEXT NOT NULL, scrap_value REAL NOT NULL, disposed_date TEXT NOT NULL, method TEXT NOT NULL, donation_location TEXT DEFAULT 'N/A', approved_by TEXT NOT NULL)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_branch_id ON assets(branch_id)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_maintenance_asset_id ON maintenance(asset_id)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_level ON audit_logs(log_level)")
conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email))")
conn.commit()
conn.close()

if is_production:
    password_hashes = query_rows("SELECT password_hash FROM users")
    if any(not row["password_hash"].startswith(("scrypt:", "pbkdf2:")) for row in password_hashes):
        raise RuntimeError("Plaintext or unsupported password hashes must be reset before production startup.")

def current_user():
    user_id = session.get("user_id")
    rows = query_rows("SELECT * FROM users WHERE id = ?", (user_id,)) if user_id else []
    return dict(rows[0]) if rows else None

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login_page"))
        if session.get("_password_reset_required") and request.endpoint not in {"settings_password_page", "change_password", "logout", "static"}:
            flash("Set a new password to continue.")
            return redirect(url_for("settings_password_page"))
        return view(*args, **kwargs)
    return wrapped

@app.context_processor
def shared_template_context():
    user = current_user()
    csrf_token = session.get("_csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session["_csrf_token"] = csrf_token
    return {"current_user": user, "profile_image": get_setting("profile_image", ""), "csrf_token": csrf_token}

def get_setting(key, default=""):
    rows = query_rows("SELECT value FROM app_settings WHERE key = ?", (key,))
    return rows[0]["value"] if rows else default

def set_setting(key, value):
    execute_commit("INSERT INTO app_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

def audit(action, target="System", level="INFO"):
    user = current_user()
    execute_commit("INSERT INTO audit_logs(timestamp, username, asset_info, action_taken, log_level) VALUES(?, ?, ?, ?, ?)",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["email"] if user else "System", target, action, level))

@app.route("/auth/login")
def login_page():
    return render_template("login.html")

@app.route("/auth/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/auth/register", methods=["POST"])
def register_user():
    form = request.form
    name = (form.get("org_name") or form.get("email", "")).strip()
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    if query_scalar("SELECT COUNT(*) FROM users"):
        flash("Registration is closed. Ask an administrator to create your account.")
        return redirect(url_for("login_page"))
    if not name or not email or len(password) < 8:
        flash("Enter an organization name, a valid email, and a password of at least 8 characters.")
        return redirect(url_for("signup_page"))
    if password != form.get("confirm_password"):
        flash("Passwords do not match.")
        return redirect(url_for("signup_page"))
    try:
        execute_commit("INSERT INTO users(name, email, password_hash, role, branch_assigned, last_login) VALUES(?, ?, ?, 'admin', 'Unassigned', 'Never')",
                       (name, email, generate_password_hash(password)))
    except sqlite3.IntegrityError:
        flash("That email is already registered.")
        return redirect(url_for("login_page"))
    user = query_rows("SELECT * FROM users WHERE email = ?", (email,))[0]
    session.clear()
    session["user_id"] = user["id"]
    audit("Account registered", email)
    return redirect(url_for("dashboard"))

@app.route("/auth/verify", methods=["POST"])
def verify_login():
    email = request.form.get("email", "").strip().lower()
    rows = query_rows("SELECT * FROM users WHERE lower(email) = ?", (email,))
    password = request.form.get("password", "")
    valid = rows and (check_password_hash(rows[0]["password_hash"], password) or rows[0]["password_hash"] == password)
    if not valid:
        flash("Invalid email or password.")
        return redirect(url_for("login_page"))
    user = rows[0]
    password_reset_required = user["password_hash"] == password
    session.clear()
    session["user_id"] = user["id"]
    if password_reset_required:
        session["_password_reset_required"] = True
    execute_commit("UPDATE users SET last_login = ? WHERE id = ?", (datetime.now().strftime("%Y-%m-%d %H:%M"), user["id"]))
    audit("User logged in", email)
    if password_reset_required:
        return redirect(url_for("settings_password_page"))
    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/")
@login_required
def dashboard():
    t = query_scalar("SELECT COUNT(*) FROM assets")
    a = query_scalar("SELECT COUNT(*) FROM assets WHERE status = 'Active'")
    i = query_scalar("SELECT COUNT(*) FROM assets WHERE status = 'Idle'")
    p = query_scalar("SELECT COUNT(*) FROM maintenance WHERE status != 'Completed'")
    v = query_scalar("SELECT SUM(cost) FROM assets")
    stats = {"total_assets": t, "active_assets": a, "idle_assets": i, "pending_maintenance": p, "total_value": f"KES {float(v):,.2f}"}
    return render_template("dashboard.html", stats=stats, notices=[{"title": "Annual Asset Audit", "date": "Aug 24, 2026"}])

@app.route("/branches")
@login_required
def branches_page():
    records = query_rows("SELECT * FROM branches ORDER BY id DESC")
    processed = []
    for row in records:
        d = dict(row)
        curr = query_scalar("SELECT COUNT(*) FROM assets WHERE branch_id = ?", (d["id"],))
        d["current_assets"] = curr
        d["utilization"] = int((curr / d["max_assets"]) * 100) if d["max_assets"] > 0 else 0
        processed.append(d)
    count = query_scalar("SELECT COUNT(*) FROM branches")
    return render_template("branches.html", branches=processed, count=count)

@app.route("/branches/add", methods=["POST"])
@login_required
def add_branch():
    form = request.form
    try:
        execute_commit("INSERT INTO branches(name, address, manager_name, manager_email, manager_contact, max_assets, status) VALUES(?, ?, ?, ?, ?, ?, 'active')",
                       (form.get("name"), form.get("address"), form.get("manager_name"), form.get("manager_email"), form.get("manager_contact"), int(form.get("max_assets", 0))))
        audit("Branch created", form.get("name"))
    except (sqlite3.IntegrityError, ValueError):
        flash("Branch could not be created. Check the details and ensure its name is unique.")
    return redirect(url_for("branches_page"))

@app.route("/branches/delete/<int:branch_id>")
@login_required
def delete_branch(branch_id):
    asset_count = query_scalar("SELECT COUNT(*) FROM assets WHERE branch_id = ?", (branch_id,))
    if asset_count:
        flash(f"This branch has {asset_count} assigned asset(s). Move them before deleting the branch.")
        return redirect(url_for("branches_page"))
    execute_commit("DELETE FROM branches WHERE id = ?", (branch_id,))
    audit("Branch deleted", str(branch_id), "WARNING")
    return redirect(url_for("branches_page"))

@app.route("/branches/edit/<int:branch_id>", methods=["POST"])
@login_required
def edit_branch(branch_id):
    form = request.form
    try:
        execute_commit("UPDATE branches SET name = ?, address = ?, manager_name = ? WHERE id = ?",
                       (form.get("name"), form.get("address"), form.get("manager_name"), branch_id))
        audit("Branch updated", str(branch_id))
    except sqlite3.IntegrityError:
        flash("That branch name is already in use.")
    return redirect(url_for("branches_page"))

@app.route("/branches/export")
@login_required
def export_branches():
    rows = query_rows("SELECT name, address, manager_name, manager_email, manager_contact, max_assets, status FROM branches ORDER BY name")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Address", "Manager", "Manager Email", "Manager Contact", "Maximum Assets", "Status"])
    writer.writerows([tuple(row) for row in rows])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), as_attachment=True, download_name="branches.csv", mimetype="text/csv")

@app.route("/branches/import", methods=["POST"])
@login_required
def import_branches():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV or Excel file to import.")
        return redirect(url_for("branches_page"))
    filename = secure_filename(upload.filename).lower()
    try:
        if filename.endswith(".csv"):
            rows = csv.DictReader(io.TextIOWrapper(upload.stream, encoding="utf-8-sig"))
        elif filename.endswith(".xlsx"):
            from openpyxl import load_workbook
            workbook = load_workbook(upload, read_only=True, data_only=True)
            sheet = workbook.active
            values = list(sheet.values)
            headers = [str(value).strip().lower().replace(" ", "_") for value in values[0]]
            rows = (dict(zip(headers, row)) for row in values[1:])
        else:
            raise ValueError("unsupported")
        for row in rows:
            execute_commit("INSERT OR IGNORE INTO branches(name, address, manager_name, manager_email, manager_contact, max_assets, status) VALUES(?, ?, ?, ?, ?, ?, 'active')",
                           (row.get("name"), row.get("address", ""), row.get("manager_name", row.get("manager", "")), row.get("manager_email", ""), row.get("manager_contact", ""), int(row.get("max_assets", 0) or 0)))
        audit("Branches imported", filename)
    except (ValueError, ImportError, KeyError):
        flash("Import failed. Use CSV or XLSX with the exported branch column headings.")
    return redirect(url_for("branches_page"))

@app.route("/branches/view/<int:branch_id>")
@login_required
def view_branch_workspace(branch_id):
    branch_rows = query_rows("SELECT * FROM branches WHERE id = ?", (branch_id,))
    branch_data = branch_rows[0] if branch_rows else None
    if branch_data is None:
        abort(404)
    search = request.args.get("search", "").strip()
    if search:
        pattern = f"%{search}%"
        assets = query_rows(
            "SELECT * FROM assets WHERE branch_id = ? AND (name LIKE ? OR serial_no LIKE ? OR model LIKE ? OR category LIKE ? OR location_room LIKE ? OR status LIKE ?) ORDER BY id DESC",
            (branch_id, pattern, pattern, pattern, pattern, pattern, pattern),
        )
    else:
        assets = query_rows("SELECT * FROM assets WHERE branch_id = ? ORDER BY id DESC", (branch_id,))
    return render_template("branch_workspace.html", branch=branch_data, assets=assets, search_query=search)

@app.route("/assets/add/<int:branch_id>", methods=["POST"])
@login_required
def add_asset_to_branch(branch_id):
    f = request.form
    branch_exists = query_scalar("SELECT COUNT(*) FROM branches WHERE id = ?", (branch_id,))
    if not branch_exists:
        abort(404)
    name, serial_no, model = (f.get(key, "").strip() for key in ("name", "serial_no", "model"))
    category, location = (f.get(key, "").strip() for key in ("category", "location_room"))
    purchased_date = f.get("purchased_date", "").strip()
    status = f.get("status", "Active").strip()
    try:
        cost = float(f.get("cost", ""))
        datetime.strptime(purchased_date, "%Y-%m-%d")
        if not all((name, serial_no, model, category, location)) or not math.isfinite(cost) or cost < 0 or status not in {"Active", "Idle", "Maintenance"}:
            raise ValueError
        execute_commit("INSERT INTO assets (name, serial_no, model, category, location_room, purchased_date, cost, status, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (name, serial_no, model, category, location, purchased_date, cost, status, branch_id))
    except (ValueError, sqlite3.IntegrityError):
        flash("Asset could not be saved. Check the details and ensure its serial number is unique.")
    else:
        audit("Asset added to branch", serial_no)
    return redirect(url_for("view_branch_workspace", branch_id=branch_id))

@app.route("/branches/<int:branch_id>/assets/export")
@login_required
def export_branch_assets(branch_id):
    if not query_scalar("SELECT COUNT(*) FROM branches WHERE id = ?", (branch_id,)):
        abort(404)
    columns = ("name", "serial_no", "model", "category", "location_room", "purchased_date", "cost", "status")
    rows = query_rows(f"SELECT {', '.join(columns)} FROM assets WHERE branch_id = ? ORDER BY id", (branch_id,))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    writer.writerows([tuple(row) for row in rows])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")), as_attachment=True,
                     download_name=f"branch-{branch_id}-assets.csv", mimetype="text/csv")

@app.route("/branches/<int:branch_id>/assets/import", methods=["POST"])
@login_required
def import_branch_assets(branch_id):
    if not query_scalar("SELECT COUNT(*) FROM branches WHERE id = ?", (branch_id,)):
        abort(404)
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV file to import.")
        return redirect(url_for("view_branch_workspace", branch_id=branch_id))
    if not secure_filename(upload.filename).lower().endswith(".csv"):
        flash("Asset import accepts CSV files only.")
        return redirect(url_for("view_branch_workspace", branch_id=branch_id))

    columns = ("name", "serial_no", "model", "category", "location_room", "purchased_date", "cost", "status")
    try:
        reader = csv.DictReader(io.StringIO(upload.read().decode("utf-8-sig")))
        headers = {str(header or "").strip().lower().replace(" ", "_") for header in (reader.fieldnames or [])}
        if not set(columns).issubset(headers):
            raise ValueError
        records = []
        for row in reader:
            values = {str(key or "").strip().lower().replace(" ", "_"): (value or "").strip() for key, value in row.items() if key}
            name, serial_no, model, category, location, purchased_date = (values.get(key, "") for key in columns[:6])
            cost = float(values.get("cost", ""))
            status = values.get("status", "Active") or "Active"
            datetime.strptime(purchased_date, "%Y-%m-%d")
            if not all((name, serial_no, model, category, location)) or not math.isfinite(cost) or cost < 0 or status not in {"Active", "Idle", "Maintenance"}:
                raise ValueError
            records.append((name, serial_no, model, category, location, purchased_date, cost, status, branch_id))
        if not records:
            raise ValueError
        conn = database_connection()
        try:
            conn.executemany("INSERT INTO assets (name, serial_no, model, category, location_room, purchased_date, cost, status, branch_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", records)
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            raise
        finally:
            conn.close()
    except (ValueError, UnicodeDecodeError, csv.Error, sqlite3.IntegrityError):
        flash("Import failed. Use the exported CSV headings, valid dates and costs, and unique serial numbers.")
    else:
        audit("Branch assets imported", f"branch {branch_id}: {len(records)} asset(s)")
        flash(f"Imported {len(records)} asset(s).")
    return redirect(url_for("view_branch_workspace", branch_id=branch_id))

@app.route("/maintenance")
@login_required
def maintenance_page():
    schedules = query_rows("SELECT * FROM maintenance ORDER BY scheduled_date ASC")
    p = query_scalar("SELECT COUNT(*) FROM maintenance WHERE status = 'Pending'")
    i = query_scalar("SELECT COUNT(*) FROM maintenance WHERE status = 'In Progress'")
    o = query_scalar("SELECT COUNT(*) FROM maintenance WHERE status = 'Overdue'")
    c = query_scalar("SELECT COUNT(*) FROM maintenance WHERE status = 'Completed'")
    return render_template("maintenance.html", schedules=schedules, m_stats={"pending": p, "in_progress": i, "overdue": o, "completed": c})

@app.route("/maintenance/generate")
@login_required
def generate_maintenance_schedules():
    all_assets = query_rows("SELECT * FROM assets")
    for asset in all_assets:
        if query_scalar("SELECT COUNT(*) FROM maintenance WHERE asset_id = ?", (asset["id"],)) > 0:
            continue
        try:
            p_date = datetime.strptime(asset["purchased_date"], "%Y-%m-%d")
        except:
            continue
        days = 180 if any(k in asset["category"].lower() for k in ["elec", "hard", "comp"]) else 360
        next_date = p_date + timedelta(days=days)
        execute_commit("INSERT INTO maintenance (asset_name, scheduled_date, priority, status, technician, est_cost, asset_id) VALUES (?, ?, 'High', 'Pending', 'SAMS Tech Core', ?, ?)", 
                     (asset["name"], next_date.strftime("%Y-%m-%d"), float(asset["cost"]) * 0.015, asset["id"]))
    return redirect(url_for("maintenance_page"))

@app.route("/reports")
@login_required
def reports_page():
    v = query_scalar("SELECT SUM(cost) FROM assets")
    inventory_items = query_rows("SELECT a.*, b.name as branch_name FROM assets a LEFT JOIN branches b ON a.branch_id = b.id ORDER BY a.category ASC")
    return render_template("reports.html", report_stats={"total_cost": f"KES {float(v):,.2f}", "expiring_soon": 0}, items=inventory_items)

@app.route("/audit")
@login_required
def audit_page():
    search = request.args.get("search", "")
    level = request.args.get("level", "All")
    clauses, args = [], []
    if level != "All":
        clauses.append("log_level = ?")
        args.append(level)
    if search:
        clauses.append("(username LIKE ? OR asset_info LIKE ? OR action_taken LIKE ?)")
        args.extend([f"%{search}%"] * 3)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    logs = query_rows(f"SELECT * FROM audit_logs{where} ORDER BY id DESC", args)
    info_c = query_scalar("SELECT COUNT(*) FROM audit_logs WHERE log_level = 'INFO'")
    warn_c = query_scalar("SELECT COUNT(*) FROM audit_logs WHERE log_level = 'WARNING'")
    err_c = query_scalar("SELECT COUNT(*) FROM audit_logs WHERE log_level = 'ERROR'")
    crit_c = query_scalar("SELECT COUNT(*) FROM audit_logs WHERE log_level = 'CRITICAL'")
    counts = {"info": info_c, "warning": warn_c, "error": err_c, "critical": crit_c}
    return render_template("audit_trails.html", logs=logs, search_query=search, current_level=level, counts=counts)

@app.route("/audit/clear", methods=["POST"])
@login_required
def clear_audit_logs():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("_csrf_token", "")
    if not session_token or not secrets.compare_digest(submitted_token, session_token):
        abort(400)
    execute_commit("DELETE FROM audit_logs")
    return redirect(url_for("audit_page"))

@app.route("/users")
@login_required
def users_page():
    search = request.args.get("search", "")
    team_members = query_rows("SELECT * FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY id DESC", (f"%{search}%", f"%{search}%"))
    total_team = query_scalar("SELECT COUNT(*) FROM users")
    branches_list = query_rows("SELECT name FROM branches ORDER BY name ASC")
    return render_template("users.html", members=team_members, count=total_team, branches=branches_list, search_query=search)

@app.route("/users/add", methods=["POST"])
@login_required
def add_user_credentials():
    f = request.form
    password = f.get("password") or secrets.token_urlsafe(10)
    execute_commit("INSERT INTO users (name, email, password_hash, role, branch_assigned, last_login) VALUES (?, ?, ?, ?, ?, 'Never')", 
                 (f.get("name"), f.get("email"), generate_password_hash(password), f.get("role"), f.get("branch") or "Unassigned"))
    audit("User account created", f.get("email"))
    return redirect(url_for("users_page"))

@app.route("/users/delete/<int:user_id>")
@login_required
def delete_user(user_id):
    if current_user() and current_user()["id"] == user_id:
        flash("You cannot delete the account currently in use.")
    else:
        execute_commit("DELETE FROM users WHERE id = ?", (user_id,))
        audit("User account deleted", str(user_id), "WARNING")
    return redirect(url_for("users_page"))

@app.route("/reports/download")
@login_required
def download_report():
    rows = query_rows("SELECT a.name, a.serial_no, a.model, a.category, b.name AS branch, a.status, a.cost FROM assets a LEFT JOIN branches b ON b.id = a.branch_id ORDER BY a.category")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Asset", "Serial Number", "Model", "Category", "Branch", "Status", "Cost"])
    writer.writerows([tuple(row) for row in rows])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), as_attachment=True, download_name="asset-report.csv", mimetype="text/csv")

@app.route("/settings")
@login_required
def settings_page():
    defaults = {"admin_name": "John Kuria", "admin_email": "johnykuria64@gmail.com", "currency": "KES", "date_format": "%Y-%m-%d %I:%M %p", "backup_interval": "daily", "theme_mode": "light", "sidebar_style": "expanded", "alert_maintenance": "enabled"}
    config_data = {key: get_setting(key, value) for key, value in defaults.items()}
    user = current_user()
    if user:
        config_data["admin_name"], config_data["admin_email"] = user["name"], user["email"]
    return render_template("settings.html", config_data=config_data)

@app.route("/settings/password")
@login_required
def settings_password_page():
    return render_template("change_password.html")

@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("_csrf_token", "")
    if not session_token or not secrets.compare_digest(submitted_token, session_token):
        abort(400)

    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    if not user or not (check_password_hash(user["password_hash"], current_password) or user["password_hash"] == current_password):
        flash("Current password is incorrect.")
        return redirect(url_for("settings_password_page"))
    if len(new_password) < 8 or new_password != request.form.get("confirm_password"):
        flash("New passwords must match and contain at least 8 characters.")
        return redirect(url_for("settings_password_page"))

    execute_commit("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))
    session.pop("_password_reset_required", None)
    audit("Password changed", user["email"])
    flash("Password updated.")
    return redirect(url_for("settings_page"))

@app.route("/settings/save", methods=["POST"])
@login_required
def save_settings():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("_csrf_token", "")
    if not session_token or not secrets.compare_digest(submitted_token, session_token):
        abort(400)

    upload = request.files.get("profile_image")
    upload_ext = ""
    if upload and upload.filename:
        upload_ext = os.path.splitext(secure_filename(upload.filename))[1].lower()
        if upload_ext not in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            flash("Profile image must be PNG, JPG, GIF, or WebP.", "error")
            return redirect(url_for("settings_page"))

    user = current_user()
    if user:
        execute_commit("UPDATE users SET name = ?, email = ? WHERE id = ?", (request.form.get("admin_name"), request.form.get("admin_email"), user["id"]))
    for key in ("currency", "date_format", "backup_interval", "theme_mode", "sidebar_style", "alert_maintenance"):
        if key in request.form:
            set_setting(key, request.form[key])
    if upload and upload.filename:
        name = f"profile_{session.get('user_id')}{upload_ext}"
        upload.save(os.path.join(UPLOAD_FOLDER, name))
        set_setting("profile_image", url_for("static", filename=f"uploads/{name}"))
    flash("Settings saved.", "success")
    return redirect(url_for("settings_page"))

@app.route("/settings/backup")
@login_required
def download_database_backup():
    user = current_user()
    if not user or user["role"].casefold() != "admin":
        abort(403)

    file_descriptor, backup_path = tempfile.mkstemp(prefix="sams-backup-", suffix=".db")
    os.close(file_descriptor)
    try:
        with closing(database_connection()) as source:
            with closing(sqlite3.connect(backup_path)) as destination:
                source.backup(destination)
    except sqlite3.Error:
        os.remove(backup_path)
        raise

    response = send_file(
        backup_path,
        as_attachment=True,
        download_name=f"smart-asset-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db",
        mimetype="application/vnd.sqlite3",
    )
    response.headers["Cache-Control"] = "no-store"
    def remove_backup_file():
        try:
            os.remove(backup_path)
        except FileNotFoundError:
            pass

    response.call_on_close(remove_backup_file)
    return response

@app.route("/junk")
@login_required
def junk_page():
    search = request.args.get("search", "").strip()
    if search:
        pattern = f"%{search}%"
        junk_items = query_rows(
            "SELECT * FROM junk_assets WHERE name LIKE ? OR serial_no LIKE ? OR category LIKE ? OR reason LIKE ? OR method LIKE ? OR donation_location LIKE ? OR approved_by LIKE ? ORDER BY id DESC",
            (pattern, pattern, pattern, pattern, pattern, pattern, pattern),
        )
    else:
        junk_items = query_rows("SELECT * FROM junk_assets ORDER BY id DESC")
    total_junk = query_scalar("SELECT COUNT(*) FROM junk_assets")
    v_sum = query_scalar("SELECT SUM(scrap_value) FROM junk_assets")
    j_stats = {"count": total_junk, "value": f"KES {float(v_sum):,.2f}"}
    return render_template("junk_assets.html", items=junk_items, stats=j_stats, search_query=search)

@app.route("/junk/delete/<int:junk_id>", methods=["POST"])
@login_required
def delete_junk_asset(junk_id):
    if not query_scalar("SELECT COUNT(*) FROM junk_assets WHERE id = ?", (junk_id,)):
        abort(404)
    execute_commit("DELETE FROM junk_assets WHERE id = ?", (junk_id,))
    audit("Junk asset record deleted", str(junk_id), "WARNING")
    flash("Disposal record deleted.")
    return redirect(url_for("junk_page"))

@app.route("/junk/export")
@login_required
def export_junk_assets():
    rows = query_rows("SELECT name, serial_no, category, reason, scrap_value, disposed_date, method, donation_location, approved_by FROM junk_assets ORDER BY id DESC")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Asset", "Serial Number", "Category", "Reason", "Scrap Value", "Disposed Date", "Method", "Donation Location", "Approved By"])
    writer.writerows([tuple(row) for row in rows])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), as_attachment=True, download_name="junk-assets.csv", mimetype="text/csv")

@app.route("/assets/junk/<int:asset_id>", methods=["POST"])
@login_required
def process_asset_lifecycle_writeoff(asset_id):
    asset_rows = query_rows("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset_rows:
        abort(404)
    asset = asset_rows[0]
    conn = database_connection()
    try:
        conn.execute("INSERT INTO junk_assets (name, serial_no, category, reason, scrap_value, disposed_date, method, donation_location, approved_by) VALUES (?, ?, ?, 'Decommissioned', ?, ?, 'scrapped', 'N/A', 'Admin')",
                     (asset["name"], asset["serial_no"], asset["category"], float(asset["cost"]) * 0.10, datetime.now().strftime("%Y-%m-%d")))
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("This asset could not be decommissioned because its serial number already exists in junk inventory.")
    else:
        audit("Asset decommissioned", asset["serial_no"], "WARNING")
        flash("Asset moved to junk inventory.")
    finally:
        conn.close()
    return redirect(url_for("view_branch_workspace", branch_id=asset["branch_id"]))

if __name__ == "__main__":
    from waitress import serve

    serve(app, host=os.environ.get("SAMS_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
