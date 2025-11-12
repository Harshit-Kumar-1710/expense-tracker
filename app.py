# app.py — Full corrected file for Expense Tracker (Flask + MySQL)
import os
import re
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for, flash
)
from markupsafe import Markup

from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from dotenv import load_dotenv
import mysql.connector
import smtplib
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer

# ---------------- SETUP ----------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# ---------------- DATABASE ----------------
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "expense_tracker")
    )

# ---------------- USER MODEL ----------------
class User(UserMixin):
    def __init__(self, id, name, email, password, budget_limit=5000.0, created_at=None, **kwargs):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
        try:
            self.budget_limit = float(budget_limit) if budget_limit is not None else 5000.0
        except:
            self.budget_limit = 5000.0
        self.created_at = created_at

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    conn.close()
    if user_data:
        return User(**user_data)
    return None

# ---------------- UTIL ----------------
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

def valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def strong_password(pw: str) -> bool:
    # minimum 8 chars and at least one digit; adjust rules as needed
    return len(pw) >= 8 and any(ch.isdigit() for ch in pw)

def send_html_email(to_email: str, subject: str, html_body: str):
    """
    Send HTML email using SMTP (Gmail).
    Returns (True, message) on success, (False, error_str) on failure.
    """
    sender = os.getenv("EMAIL_USER")
    app_pass = os.getenv("EMAIL_PASS")
    if not sender or not app_pass:
        app.logger.warning("Email credentials not set in .env (EMAIL_USER/EMAIL_PASS). Skipping send.")
        return False, "Missing email credentials"
    msg = MIMEText(html_body, "html")
    msg["Subject"] = subject
    msg["From"] = f"Expense Tracker Alerts <{sender}>"
    msg["To"] = to_email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(sender, app_pass)
            smtp.send_message(msg)
        return True, "Email sent"
    except Exception as e:
        app.logger.exception("Failed to send email")
        return False, str(e)

def send_email(to_email: str, subject: str, body_text: str):
    """
    Wrapper for plaintext emails (used by forgot-password flow).
    """
    return send_html_email(to_email, subject, f"<pre style='font-family:inherit'>{body_text}</pre>")

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return render_template("index.html", message=f"🚀 Welcome back, {current_user.name}!")
    return render_template("index.html", message="✨ Welcome to Expense Tracker — please log in or sign up to continue!")

# ---------- SIGNUP ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not valid_email(email):
            flash("Please provide a valid name and email.", "danger")
            return render_template("signup.html")

        if not strong_password(password):
            flash("Password must be at least 8 characters long and contain a number.", "danger")
            return render_template("signup.html")

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            cur.close()
            conn.close()
            flash("⚠️ This email is already registered. Please log in instead.", "warning")
            return redirect(url_for("login"))

        # Insert new user
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = "remember" in request.form

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()

        if user_data and bcrypt.check_password_hash(user_data.get("password", ""), password):
            user = User(**user_data)
            login_user(user, remember=remember)
            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid email or password. Please try again.", "danger")

    return render_template("login.html")

# ---------------- FORGOT / RESET PASSWORD ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not valid_email(email):
            flash("Please provide a valid email address.", "danger")
            return render_template("forgot_password.html")

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            token = serializer.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)

            subject = "🔑 Expense Tracker Password Reset"
            body = f"Hi {user['name']},\n\nClick the link below to reset your password:\n\n{reset_url}\n\nThis link will expire in 10 minutes.\n\n- Expense Tracker Team"

            sent, info = send_email(user["email"], subject, body)
            if sent:
                flash("📩 Password reset link sent to your email!", "success")
            else:
                flash(f"⚠️ Failed to send reset email: {info}", "warning")
        else:
            flash("❌ No account found with this email.", "danger")

    return render_template("forgot_password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=600)  # 600s = 10 minutes
    except Exception:
        flash("❌ The reset link is invalid or expired.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        if not strong_password(new_password):
            flash("New password must be at least 8 characters and include a number.", "danger")
            return render_template("reset_password.html")

        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_pw, email))
        conn.commit()
        cur.close()
        conn.close()

        flash("✅ Password updated successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------- LOGOUT ----------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 You’ve been logged out!", "info")
    return redirect(url_for("login"))

# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

# ---------- ADD EXPENSE ----------
@app.route("/add-expense", methods=["GET", "POST"])
@login_required
def add_expense():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # fetch categories for this user
    cur.execute("SELECT id, name FROM categories WHERE user_id = %s ORDER BY id DESC", (current_user.id,))
    categories = cur.fetchall()

    if request.method == "POST":
        category_id = request.form.get("category")
        amount = request.form.get("amount")
        note = request.form.get("note", "").strip()
        date_str = request.form.get("date")  # expected YYYY-MM-DD

        # validation
        if not category_id or not amount or not date_str:
            flash("Please fill all fields.", "danger")
            cur.close()
            conn.close()
            return render_template("add_expense.html", categories=categories)

        try:
            amount_val = float(amount)
            spent_on = datetime.strptime(date_str, "%Y-%m-%d").date()
        except Exception:
            flash("Invalid amount or date format.", "danger")
            cur.close()
            conn.close()
            return render_template("add_expense.html", categories=categories)

        cur.execute(
            "INSERT INTO transactions (user_id, category_id, amount, note, spent_on) VALUES (%s, %s, %s, %s, %s)",
            (current_user.id, category_id, amount_val, note, spent_on)
        )
        conn.commit()

        # Budget alert check
        cur.execute("SELECT SUM(amount) AS total FROM transactions WHERE user_id = %s", (current_user.id,))
        row = cur.fetchone()
        total_spent = row.get("total") if row else 0.0
        total_spent = float(total_spent or 0.0)

        if total_spent > current_user.budget_limit:
            # send short HTML snippet email
            html_body = render_template("report_email_snippet.html",
                                        user=current_user,
                                        total_spent=total_spent,
                                        budget_limit=current_user.budget_limit,
                                        short_msg=True)
            send_html_email(current_user.email, "⚠️ Expense Tracker Budget Alert", html_body)

        flash("✅ Expense added successfully!", "success")
        cur.close()
        conn.close()
        return redirect(url_for("dashboard"))

    cur.close()
    conn.close()
    return render_template("add_expense.html", categories=categories)

# ---------- CATEGORIES ----------
@app.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            cur.execute("INSERT INTO categories (user_id, name) VALUES (%s, %s)", (current_user.id, name))
            conn.commit()
            flash("✅ Category added!", "success")
    cur.execute("SELECT id, name FROM categories WHERE user_id = %s ORDER BY id DESC", (current_user.id,))
    cats = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("categories.html", categories=cats)

# ---------- TRANSACTIONS ----------
@app.route("/transactions")
@login_required
def transactions():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT t.id, c.name AS category, t.amount, t.note, t.spent_on
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = %s
        ORDER BY t.spent_on DESC
    """, (current_user.id,))
    data = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("transactions.html", transactions=data)

# ---------- EMAIL + ON-SCREEN REPORT ----------
@app.route("/email-report")
@login_required
def email_report():
    """
    Query param: ?range=week  or ?range=month
    Renders full report on screen and sends the same HTML to the user's email.
    """
    period = request.args.get("range", "month")
    end_date = datetime.utcnow().date()
    if period == "week":
        start_date = end_date - timedelta(days=7)
        label = "Last 7 days"
    else:
        start_date = end_date - timedelta(days=30)
        label = "Last 30 days"

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT t.amount, t.note, t.spent_on, c.name AS category
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = %s AND t.spent_on BETWEEN %s AND %s
        ORDER BY t.spent_on DESC
    """, (current_user.id, start_date, end_date))
    transactions = cur.fetchall()

    cur.execute("""
        SELECT c.name AS category, SUM(t.amount) AS total
        FROM transactions t
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.user_id = %s AND t.spent_on BETWEEN %s AND %s
        GROUP BY c.name
        ORDER BY total DESC
    """, (current_user.id, start_date, end_date))
    category_totals = cur.fetchall()

    total_sum = sum([t["amount"] for t in transactions]) if transactions else 0.0

    cur.close()
    conn.close()

    report_html = render_template("report_email.html",
                                  user=current_user,
                                  transactions=transactions,
                                  category_totals=category_totals,
                                  total_sum=total_sum,
                                  period_label=label,
                                  start_date=start_date,
                                  end_date=end_date)

    sent, info = send_html_email(current_user.email, f"Expense Tracker Report - {label}", report_html)
    if sent:
        flash(Markup(f"📧 Report emailed to <b>{current_user.email}</b>"), "success")
    else:
        flash(f"⚠️ Report email failed: {info}", "warning")

    return render_template("report.html",
                           user=current_user,
                           transactions=transactions,
                           category_totals=category_totals,
                           total_sum=total_sum,
                           period_label=label,
                           start_date=start_date,
                           end_date=end_date)

# ---------- PROFILE (basic) ----------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not valid_email(email):
            flash("Please provide valid name and email.", "danger")
            return redirect(url_for("profile"))

        conn = get_db_connection()
        cur = conn.cursor()

        # check duplicate email if changed
        if email != current_user.email:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash("Email already in use.", "danger")
                cur.close()
                conn.close()
                return redirect(url_for("profile"))

        if password:
            if not strong_password(password):
                flash("New password must be at least 8 characters and include a number.", "danger")
                cur.close()
                conn.close()
                return redirect(url_for("profile"))
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            cur.execute("UPDATE users SET name=%s, email=%s, password=%s WHERE id=%s",
                        (name, email, hashed_pw, current_user.id))
        else:
            cur.execute("UPDATE users SET name=%s, email=%s WHERE id=%s", (name, email, current_user.id))

        conn.commit()
        cur.close()
        conn.close()
        flash("✅ Profile updated. Please log in again if email/password changed.", "success")
        return redirect(url_for("dashboard"))

    return render_template("profile.html", user=current_user)

# ---------- BUDGET PAGE ----------
@app.route("/budget", methods=["GET", "POST"])
@login_required
def budget():
    if request.method == "POST":
        try:
            new_limit = float(request.form.get("budget_limit"))
        except Exception:
            flash("Invalid budget value.", "danger")
            return redirect(url_for("budget"))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET budget_limit = %s WHERE id = %s", (new_limit, current_user.id))
        conn.commit()
        cur.close()
        conn.close()
        flash("✅ Budget limit updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("budget.html", budget_limit=current_user.budget_limit)

# ---------------- RUN APP ----------------
if __name__ == "__main__":
    app.run(debug=True)
