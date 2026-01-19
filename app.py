from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

app.secret_key = "my_secret_key_for_session"

DB_NAME = "student_data.db"


def get_db():
   ### Open a connection to the database ###
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def setup_db():
    ### Create tables the first time the app runs ###
    if os.path.exists(DB_NAME):
        return

    connection = get_db()
    cursor = connection.cursor()

    # students
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            grade TEXT,
            allow_analytics INTEGER DEFAULT 0,
            show_in_classlist INTEGER DEFAULT 1,
            deletion_requested INTEGER DEFAULT 0
        )
    """)

    # admin
    cursor.execute("""
        CREATE TABLE admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    # default admin account (admin / admin26)
    admin_pw = generate_password_hash("admin26")
    cursor.execute(
        "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
        ("admin", admin_pw),
    )

    connection.commit()
    connection.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        grade = request.form.get("grade", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not name or not email or not password:
            flash("Please fill in name, email and password.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        try:
            connection = get_db()
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, grade, password_hash) "
                "VALUES (?, ?, ?, ?)",
                (name, email, grade, pw_hash),
            )
            connection.commit()
            connection.close()
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            # email is already used
            flash("That email is already registered.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash("Logged in.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Wrong email or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    connection = get_db()
    cursor = connection.cursor()

    if request.method == "POST":
        allow_analytics = 1 if request.form.get("allow_analytics") else 0
        show_in_classlist = 1 if request.form.get("show_in_classlist") else 0

        cursor.execute(
            "UPDATE users SET allow_analytics = ?, show_in_classlist = ? "
            "WHERE id = ?",
            (allow_analytics, show_in_classlist, user_id),
        )
        connection.commit()
        flash("Privacy settings saved.", "success")

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    connection.close()

    return render_template("dashboard.html", user=user)


@app.route("/download_data")
def download_data():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT id, name, email, grade,
               allow_analytics, show_in_classlist, deletion_requested
        FROM users WHERE id = ?
    """, (user_id,))
    user = cursor.fetchone()
    connection.close()

    if not user:
        return jsonify({"error": "user not found"}), 404

    data = {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "grade": user["grade"],
        "allow_analytics": bool(user["allow_analytics"]),
        "show_in_classlist": bool(user["show_in_classlist"]),
        "deletion_requested": bool(user["deletion_requested"]),
    }
    return jsonify(data)


@app.route("/request_deletion", methods=["POST"])
def request_deletion():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    connection = get_db()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET deletion_requested = 1 WHERE id = ?",
        (user_id,),
    )
    connection.commit()
    connection.close()

    flash("Deletion request sent to admin.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You are logged out.", "success")
    return redirect(url_for("index"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cursor.fetchone()
        connection.close()

        if admin and check_password_hash(admin["password_hash"], password):
            session["is_admin"] = True
            flash("Admin logged in.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Wrong admin login.", "error")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("is_admin"):
        flash("Admins only.", "error")
        return redirect(url_for("admin_login"))

    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT id, name, email, grade,
               allow_analytics, show_in_classlist, deletion_requested
        FROM users
    """)
    users = cursor.fetchall()
    connection.close()

    return render_template("admin_dashboard.html", users=users)


if __name__ == "__main__":
    setup_db()
    app.run(debug=True)
