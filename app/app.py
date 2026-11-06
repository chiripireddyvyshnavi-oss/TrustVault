
import os
import secrets
import sqlite3
import uuid
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from db import get_db, init_db


# Application setup
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", secrets.token_hex(32)
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "png", "jpg", "jpeg", "xlsx"
}

init_db()


# Check allowed file extensions
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# Home page
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash("Enter all details. Password must have 8 characters.")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            user_count = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

            role = "owner" if user_count == 0 else "viewer"

            conn.execute(
                """
                INSERT INTO users
                (name, email, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    generate_password_hash(password),
                    role
                )
            )

            conn.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.")

        finally:
            conn.close()

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        finally:
            conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["name"] = user["name"]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        name=session["name"],
        role=session["role"]
    )


# View registered users
@app.route("/users")
def users():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("admin", "owner"):
        flash("You are not authorized to view registered users.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        registered_users = conn.execute(
            """
            SELECT id, name, email, role, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "users.html",
        users=registered_users
    )


# Upload document
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("Please select a file.")
            return redirect(url_for("upload"))

        file = request.files["file"]
        category = request.form.get("category", "").strip()

        if file.filename == "":
            flash("No file selected.")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):
            flash("File type not allowed.")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename)

        if not original_filename:
            flash("Invalid filename.")
            return redirect(url_for("upload"))

        stored_name = str(uuid.uuid4()) + "_" + original_filename
        file_path = UPLOAD_FOLDER / stored_name

        file.save(file_path)

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO documents
                (filename, stored_name, category, owner_id)
                VALUES (?, ?, ?, ?)
                """,
                (
                    original_filename,
                    stored_name,
                    category,
                    session["user_id"]
                )
            )

            conn.commit()
            flash("Document uploaded successfully.")

        except sqlite3.Error as error:
            conn.rollback()
            file_path.unlink(missing_ok=True)
            print("Upload database error:", error)
            flash("Could not save document.")

        finally:
            conn.close()

        return redirect(url_for("documents"))

    return render_template("upload.html")


# View own uploaded documents
@app.route("/documents")
def documents():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    try:
        uploaded_documents = conn.execute(
            """
            SELECT documents.*, users.name AS owner_name
            FROM documents
            JOIN users ON documents.owner_id = users.id
            WHERE documents.owner_id = ?
            ORDER BY documents.id DESC
            """,
            (session["user_id"],)
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "documents.html",
        documents=uploaded_documents
    )


# View shared documents
@app.route("/viewers")
def viewers():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    try:
        shared_documents = conn.execute(
            """
            SELECT documents.*, users.name AS owner_name,
                   permissions.permission
            FROM documents
            JOIN permissions
                ON documents.id = permissions.document_id
            JOIN users
                ON documents.owner_id = users.id
            WHERE permissions.user_id = ?
            AND permissions.permission IN ('read', 'edit')
            ORDER BY documents.id DESC
            """,
            (session["user_id"],)
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "viewers.html",
        documents=shared_documents
    )


# Secure document download
@app.route("/download/<int:document_id>")
def download(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    try:
        document = conn.execute(
            """
            SELECT documents.*
            FROM documents
            WHERE documents.id = ?
            AND (
                documents.owner_id = ?
                OR EXISTS (
                    SELECT 1
                    FROM permissions
                    WHERE permissions.document_id = documents.id
                    AND permissions.user_id = ?
                    AND permissions.permission IN ('read', 'edit')
                )
            )
            """,
            (
                document_id,
                session["user_id"],
                session["user_id"]
            )
        ).fetchone()

    finally:
        conn.close()

    if document is None:
        flash("Document not found or access denied.")
        return redirect(url_for("documents"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["stored_name"],
        as_attachment=True,
        download_name=document["filename"]
    )


# Share documents with registered users
@app.route("/share", methods=["GET", "POST"])
def share():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    try:
        if request.method == "POST":
            document_id = request.form.get("document_id", type=int)
            user_id = request.form.get("user_id", type=int)
            permission = request.form.get("permission", "").strip()

            if not document_id or not user_id:
                flash("Please select a document and user.")
                return redirect(url_for("share"))

            if permission not in ("read", "edit"):
                flash("Please select a valid permission.")
                return redirect(url_for("share"))

            if user_id == session["user_id"]:
                flash("You cannot share a document with yourself.")
                return redirect(url_for("share"))

            document = conn.execute(
                """
                SELECT id FROM documents
                WHERE id = ? AND owner_id = ?
                """,
                (document_id, session["user_id"])
            ).fetchone()

            if not document:
                flash("You can only share your own documents.")
                return redirect(url_for("share"))

            target_user = conn.execute(
                "SELECT id FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

            if not target_user:
                flash("Selected user does not exist.")
                return redirect(url_for("share"))

            existing_permission = conn.execute(
                """
                SELECT id FROM permissions
                WHERE document_id = ? AND user_id = ?
                """,
                (document_id, user_id)
            ).fetchone()

            if existing_permission:
                conn.execute(
                    """
                    UPDATE permissions
                    SET permission = ?, granted_by = ?
                    WHERE document_id = ? AND user_id = ?
                    """,
                    (
                        permission,
                        session["user_id"],
                        document_id,
                        user_id
                    )
                )
            else:
                conn.execute(
                    """
                    INSERT INTO permissions
                    (document_id, user_id, permission, granted_by)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        user_id,
                        permission,
                        session["user_id"]
                    )
                )

            conn.execute(
                """
                INSERT INTO audit_logs
                (actor_id, document_id, action,
                 target_user_id, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    document_id,
                    "DOCUMENT_SHARED",
                    user_id,
                    permission
                )
            )

            conn.commit()

            flash("Document shared successfully!")
            return redirect(url_for("share"))

        shared_documents = conn.execute(
            """
            SELECT id, filename
            FROM documents
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],)
        ).fetchall()

        registered_users = conn.execute(
            """
            SELECT id, name, email
            FROM users
            WHERE id != ?
            ORDER BY name
            """,
            (session["user_id"],)
        ).fetchall()

    except sqlite3.Error as error:
        conn.rollback()
        print("Sharing database error:", error)
        flash("A database error occurred while sharing the document.")

        shared_documents = conn.execute(
            """
            SELECT id, filename FROM documents
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],)
        ).fetchall()

        registered_users = conn.execute(
            """
            SELECT id, name, email FROM users
            WHERE id != ?
            ORDER BY name
            """,
            (session["user_id"],)
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "share.html",
        documents=shared_documents,
        users=registered_users
    )


# View activity history
@app.route("/audit-logs")
def audit_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ("admin", "owner"):
        flash("You are not authorized to view activity history.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        if session.get("role") == "admin":
            logs = conn.execute(
                """
                SELECT
                    audit_logs.*,
                    actor.name AS actor_name,
                    target.name AS target_name
                FROM audit_logs
                LEFT JOIN users AS actor
                    ON audit_logs.actor_id = actor.id
                LEFT JOIN users AS target
                    ON audit_logs.target_user_id = target.id
                ORDER BY audit_logs.id DESC
                """
            ).fetchall()
        else:
            logs = conn.execute(
                """
                SELECT
                    audit_logs.*,
                    actor.name AS actor_name,
                    target.name AS target_name
                FROM audit_logs
                LEFT JOIN users AS actor
                    ON audit_logs.actor_id = actor.id
                LEFT JOIN users AS target
                    ON audit_logs.target_user_id = target.id
                WHERE audit_logs.actor_id = ?
                ORDER BY audit_logs.id DESC
                """,
                (session["user_id"],)
            ).fetchall()

    finally:
        conn.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Run application
if __name__ == "__main__":
    app.run(debug=True)
