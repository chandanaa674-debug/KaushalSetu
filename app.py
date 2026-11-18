import os, sqlite3, secrets, hmac, re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)
DATABASE = os.path.join(app.instance_path, "kaushalsetu.db")
os.makedirs(app.instance_path, exist_ok=True)


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

@app.context_processor
def inject_security_helpers():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_post_requests():
    # Protect every state-changing form submission against cross-site request forgery.
    if request.method == "POST":
        supplied = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            return "Invalid or expired form token. Please refresh the page and try again.", 400

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.route("/health")
def health():
    try:
        db().execute("SELECT 1").fetchone()
        return {"status": "ok", "database": "connected"}
    except sqlite3.Error:
        return {"status": "error", "database": "unavailable"}, 503

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, role TEXT NOT NULL,
      location TEXT DEFAULT '', skills TEXT DEFAULT '',
      qualification TEXT DEFAULT '', availability TEXT DEFAULT 'Flexible'
    );
    CREATE TABLE IF NOT EXISTS jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employer_id INTEGER NOT NULL, title TEXT NOT NULL,
      category TEXT NOT NULL, skills TEXT NOT NULL,
      location TEXT NOT NULL, salary TEXT DEFAULT '',
      work_type TEXT DEFAULT 'Flexible', description TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(employer_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id INTEGER NOT NULL, youth_id INTEGER NOT NULL,
      status TEXT DEFAULT 'Applied',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(job_id, youth_id),
      FOREIGN KEY(job_id) REFERENCES jobs(id),
      FOREIGN KEY(youth_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shg_id INTEGER NOT NULL, customer TEXT NOT NULL,
      product TEXT NOT NULL, quantity INTEGER NOT NULL,
      deadline TEXT DEFAULT '', status TEXT DEFAULT 'New',
      amount REAL DEFAULT 0,
      FOREIGN KEY(shg_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS earnings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shg_id INTEGER NOT NULL, member_name TEXT NOT NULL,
      order_label TEXT DEFAULT '', amount REAL NOT NULL,
      paid INTEGER DEFAULT 0,
      FOREIGN KEY(shg_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()


def clean_text(value, max_length=250):
    value = (value or "").strip()
    if len(value) > max_length:
        raise ValueError("One of the fields is too long.")
    return value

def valid_email(value):
    value = (value or "").strip().lower()
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value)) and len(value) <= 254

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("You do not have permission to access that page.", "error")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def current_user():
    if not session.get("user_id"):
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.route("/")
def home():
    stats = {
      "jobs": db().execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
      "youth": db().execute("SELECT COUNT(*) FROM users WHERE role='youth'").fetchone()[0],
      "groups": db().execute("SELECT COUNT(*) FROM users WHERE role='shg'").fetchone()[0]
    }
    jobs = db().execute("SELECT jobs.*, users.name AS employer FROM jobs JOIN users ON users.id=jobs.employer_id ORDER BY jobs.id DESC LIMIT 3").fetchall()
    return render_template("index.html", stats=stats, jobs=jobs)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            name = clean_text(request.form.get("name"), 100)
            email = clean_text(request.form.get("email"), 254).lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            location = clean_text(request.form.get("location"), 120)
            skills = clean_text(request.form.get("skills"), 500)
            qualification = clean_text(request.form.get("qualification"), 160)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("register.html")
        if not name or not valid_email(email) or len(password) < 8 or role not in ("shg", "youth", "employer"):
            flash("Enter a valid email, choose a role, and use a password of at least 8 characters.", "error")
            return render_template("register.html")
        try:
            cur = db().execute(
              "INSERT INTO users(name,email,password,role,location,skills,qualification) VALUES(?,?,?,?,?,?,?)",
              (name,email,generate_password_hash(password),role,location,skills,qualification))
            db().commit()
            session.clear()
            session.update(user_id=cur.lastrowid, name=name, role=role)
            csrf_token()
            flash("Welcome to KaushalSetu! Your account is ready.", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("That email is already registered. Please log in.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password"], request.form.get("password", "")):
            session.clear()
            session.update(user_id=user["id"], name=user["name"], role=user["role"])
            csrf_token()
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = db()
    if user["role"] == "youth":
        jobs = conn.execute("SELECT * FROM jobs ORDER BY id DESC").fetchall()
        applications = conn.execute("""SELECT applications.*, jobs.title, jobs.location
          FROM applications JOIN jobs ON jobs.id=applications.job_id
          WHERE youth_id=? ORDER BY applications.id DESC""", (user["id"],)).fetchall()
        recommendations = sorted(jobs, key=lambda j: match_score(user["skills"], j["skills"], user["location"], j["location"]), reverse=True)[:3]
        return render_template("dashboard_youth.html", user=user, jobs=jobs, applications=applications, recommendations=recommendations, score=match_score)
    if user["role"] == "employer":
        jobs = conn.execute("SELECT * FROM jobs WHERE employer_id=? ORDER BY id DESC", (user["id"],)).fetchall()
        apps = conn.execute("""SELECT applications.*, jobs.title, users.name AS applicant, users.skills, users.location
          FROM applications JOIN jobs ON jobs.id=applications.job_id
          JOIN users ON users.id=applications.youth_id
          WHERE jobs.employer_id=? ORDER BY applications.id DESC""", (user["id"],)).fetchall()
        return render_template("dashboard_employer.html", user=user, jobs=jobs, applications=apps)
    orders = conn.execute("SELECT * FROM orders WHERE shg_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    earnings = conn.execute("SELECT * FROM earnings WHERE shg_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    totals = conn.execute("SELECT COALESCE(SUM(amount),0) FROM orders WHERE shg_id=?", (user["id"],)).fetchone()[0]
    return render_template("dashboard_shg.html", user=user, orders=orders, earnings=earnings, revenue=totals)

def match_score(youth_skills, job_skills, youth_location="", job_location=""):
    # Explainable baseline matcher: exact skill overlap (85%) + location text match (15%).
    # This is a transparent rules-based score, not a trained ML model or distance calculation.
    normalize = lambda s: {re.sub(r"\\s+", " ", x.strip().lower()) for x in (s or "").split(",") if x.strip()}
    ys, js = normalize(youth_skills), normalize(job_skills)
    skill_score = (len(ys & js) / len(js)) if js else 0
    yl = (youth_location or "").strip().lower()
    jl = (job_location or "").strip().lower()
    location_score = 1 if yl and jl and (yl in jl or jl in yl) else 0
    return round(skill_score * 85 + location_score * 15)

@app.route("/jobs")
def jobs():
    all_jobs = db().execute("SELECT jobs.*, users.name AS employer FROM jobs JOIN users ON users.id=jobs.employer_id ORDER BY jobs.id DESC").fetchall()
    return render_template("jobs.html", jobs=all_jobs)

@app.route("/jobs/create", methods=["GET", "POST"])
@login_required
@role_required("employer", "shg")
def create_job():
    if request.method == "POST":
        f = request.form
        try:
            title = clean_text(f.get("title"), 120)
            category = clean_text(f.get("category"), 80)
            skills = clean_text(f.get("skills"), 400)
            location = clean_text(f.get("location"), 120)
            salary = clean_text(f.get("salary"), 80)
            work_type = clean_text(f.get("work_type", "Flexible"), 40)
            description = clean_text(f.get("description"), 1200)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("create_job.html")
        if not all((title, category, skills, location)):
            flash("Please fill in the job title, category, skills and location.", "error")
        else:
            db().execute("""INSERT INTO jobs(employer_id,title,category,skills,location,salary,work_type,description)
              VALUES(?,?,?,?,?,?,?,?)""",
              (session["user_id"], title, category, skills, location, salary, work_type, description))
            db().commit()
            flash("Opportunity published successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("create_job.html")

@app.route("/jobs/<int:job_id>/apply", methods=["POST"])
@login_required
@role_required("youth")
def apply_job(job_id):
    job = db().execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        flash("This opportunity is no longer available.", "error")
    else:
        try:
            db().execute("INSERT INTO applications(job_id,youth_id) VALUES(?,?)", (job_id, session["user_id"]))
            db().commit()
            flash("Application submitted!", "success")
        except sqlite3.IntegrityError:
            flash("You have already applied for this opportunity.", "error")
    return redirect(request.referrer or url_for("jobs"))

@app.route("/applications/<int:app_id>/<status>", methods=["POST"])
@login_required
@role_required("employer", "shg")
def update_application(app_id, status):
    if status not in ("Shortlisted", "Selected", "Rejected"):
        return redirect(url_for("dashboard"))
    owned = db().execute("""SELECT applications.id FROM applications
      JOIN jobs ON jobs.id=applications.job_id
      WHERE applications.id=? AND jobs.employer_id=?""", (app_id, session["user_id"])).fetchone()
    if owned:
        db().execute("UPDATE applications SET status=? WHERE id=?", (status, app_id))
        db().commit()
        flash("Application status updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/orders/add", methods=["POST"])
@login_required
@role_required("shg")
def add_order():
    f = request.form
    try:
        quantity = int(f.get("quantity", "0"))
        amount = float(f.get("amount", "0") or 0)
        if quantity < 1 or amount < 0:
            raise ValueError()
        db().execute("INSERT INTO orders(shg_id,customer,product,quantity,deadline,amount) VALUES(?,?,?,?,?,?)",
          (session["user_id"], f["customer"].strip(), f["product"].strip(), quantity, f.get("deadline",""), amount))
        db().commit()
        flash("Order added to your tracker.", "success")
    except (ValueError, KeyError):
        flash("Please enter valid order details.", "error")
    return redirect(url_for("dashboard"))

@app.route("/orders/<int:order_id>/<status>", methods=["POST"])
@login_required
@role_required("shg")
def update_order(order_id, status):
    if status not in ("In production", "Ready", "Delivered"):
        return redirect(url_for("dashboard"))
    db().execute("UPDATE orders SET status=? WHERE id=? AND shg_id=?", (status, order_id, session["user_id"]))
    db().commit()
    flash("Order progress updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/earnings/add", methods=["POST"])
@login_required
@role_required("shg")
def add_earning():
    f = request.form
    try:
        amount = float(f.get("amount", "0"))
        if amount < 0 or not f.get("member_name","").strip():
            raise ValueError()
        db().execute("INSERT INTO earnings(shg_id,member_name,order_label,amount,paid) VALUES(?,?,?,?,?)",
          (session["user_id"], f["member_name"].strip(), f.get("order_label","").strip(), amount, 0))
        db().commit()
        flash("Member earning recorded.", "success")
    except ValueError:
        flash("Enter a member name and a valid amount.", "error")
    return redirect(url_for("dashboard"))

@app.route("/earnings/<int:earning_id>/paid", methods=["POST"])
@login_required
@role_required("shg")
def mark_paid(earning_id):
    db().execute("UPDATE earnings SET paid=1 WHERE id=? AND shg_id=?", (earning_id, session["user_id"]))
    db().commit()
    flash("Payment marked as paid.", "success")
    return redirect(url_for("dashboard"))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
