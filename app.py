import os, sqlite3, hashlib, shutil
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

BASE = os.path.abspath(os.path.dirname(__file__))
DB = os.path.join(BASE, "securecampus.sqlite3")
KEY_FILE = os.path.join(BASE, "secret.key")
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "replace-this-demo-secret-before-deployment")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def cipher():
    if not os.path.exists(KEY_FILE) or os.path.getsize(KEY_FILE) == 0:
        with open(KEY_FILE, "wb") as f: f.write(Fernet.generate_key())
    return Fernet(open(KEY_FILE, "rb").read())

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def audit(actor, action, detail=""):
    with db() as con:
        con.execute("INSERT INTO audit_logs(actor,action,detail,created_at) VALUES(?,?,?,?)",
                    (actor, action, detail, now()))

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','student')),
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS students(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          student_no TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
          department TEXT NOT NULL DEFAULT '', semester TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS marks(
          id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
          subject TEXT NOT NULL, total INTEGER NOT NULL CHECK(total > 0), obtained INTEGER NOT NULL CHECK(obtained >= 0 AND obtained <= total),
          updated_at TEXT NOT NULL, UNIQUE(student_id, subject)
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
          detail TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS secure_notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
          encrypted_value TEXT NOT NULL, digest TEXT NOT NULL
        );
        """)
        if not con.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                        ("admin", generate_password_hash("Admin@12345"), "admin", now()))

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("uid"): return redirect(url_for("login"))
        with db() as con:
            u = con.execute("SELECT active FROM users WHERE id=?", (session["uid"],)).fetchone()
        if not u or not u["active"]:
            session.clear(); flash("Account disabled. Admin se rabta karein."); return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*a, **kw):
        if session.get("role") != "admin":
            audit(session.get("username","unknown"), "ACCESS DENIED", request.path)
            abort(403)
        return fn(*a, **kw)
    return wrapped

@app.route("/")
def home():
    return redirect(url_for("dashboard") if session.get("uid") else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        with db() as con: u=con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if u and u["active"] and check_password_hash(u["password_hash"], password):
            session.clear(); session.update(uid=u["id"], username=u["username"], role=u["role"])
            audit(username,"LOGIN","Successful login")
            return redirect(url_for("dashboard"))
        audit(username or "unknown","LOGIN FAILED","Invalid credentials or disabled account")
        flash("Login details ghalat hain ya account disabled hai.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    audit(session["username"],"LOGOUT")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        if session["role"]=="admin":
            students=con.execute("SELECT COUNT(*) FROM students").fetchone()[0]
            users=con.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
            marks=con.execute("SELECT COUNT(*) FROM marks").fetchone()[0]
            recent=con.execute("""SELECT s.full_name,s.student_no,COUNT(m.id) subjects,
                                  COALESCE(ROUND(AVG(m.obtained*100.0/m.total),1),0) average
                                  FROM students s LEFT JOIN marks m ON m.student_id=s.id
                                  GROUP BY s.id ORDER BY s.id DESC LIMIT 6""").fetchall()
            return render_template("admin_dashboard.html", students=students, users=users, marks=marks, recent=recent)
        st=con.execute("SELECT * FROM students WHERE user_id=?", (session["uid"],)).fetchone()
        if not st: abort(403)
        rows=con.execute("SELECT * FROM marks WHERE student_id=? ORDER BY subject", (st["id"],)).fetchall()
    total_obt=sum(r["obtained"] for r in rows); total_max=sum(r["total"] for r in rows)
    average=round(total_obt*100/total_max,1) if total_max else 0
    return render_template("student_dashboard.html", student=st, marks=rows, average=average)

@app.route("/admin/students")
@admin_required
def student_list():
    q=request.args.get("q","").strip()
    with db() as con:
        rows=con.execute("""SELECT s.*,u.username,u.active FROM students s JOIN users u ON u.id=s.user_id
                            WHERE s.full_name LIKE ? OR s.student_no LIKE ? OR u.username LIKE ?
                            ORDER BY s.id DESC""", (f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    return render_template("students.html", students=rows, q=q)

@app.route("/admin/students/add", methods=["GET","POST"])
@admin_required
def add_student():
    if request.method=="POST":
        f=request.form
        username=f.get("username","").strip(); password=f.get("password","")
        student_no=f.get("student_no","").strip(); full_name=f.get("full_name","").strip()
        if not all([username,password,student_no,full_name]) or len(password)<8:
            flash("Required fields fill karein. Password kam az kam 8 characters ka ho."); return redirect(url_for("add_student"))
        try:
            with db() as con:
                cur=con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                (username,generate_password_hash(password),"student",now()))
                con.execute("""INSERT INTO students(user_id,student_no,full_name,email,department,semester,phone)
                               VALUES(?,?,?,?,?,?,?)""",
                            (cur.lastrowid,student_no,full_name,f.get("email",""),f.get("department",""),f.get("semester",""),f.get("phone","")))
            audit(session["username"],"STUDENT CREATED",f"{student_no} / {username}")
            flash("Student account create ho gaya."); return redirect(url_for("student_list"))
        except sqlite3.IntegrityError:
            flash("Username ya Student ID pehle se mojood hai.")
    return render_template("student_form.html", student=None, mode="Add")

@app.route("/admin/students/<int:sid>/edit", methods=["GET","POST"])
@admin_required
def edit_student(sid):
    with db() as con:
        st=con.execute("SELECT s.*,u.username,u.active FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,)).fetchone()
    if not st: abort(404)
    if request.method=="POST":
        f=request.form
        try:
            with db() as con:
                con.execute("""UPDATE students SET student_no=?,full_name=?,email=?,department=?,semester=?,phone=?
                               WHERE id=?""",
                            (f["student_no"].strip(),f["full_name"].strip(),f.get("email",""),f.get("department",""),f.get("semester",""),f.get("phone",""),sid))
                con.execute("UPDATE users SET username=? WHERE id=?", (f["username"].strip(),st["user_id"]))
            audit(session["username"],"STUDENT PROFILE UPDATED",st["student_no"])
            flash("Student details update ho gayi."); return redirect(url_for("student_list"))
        except sqlite3.IntegrityError: flash("Username ya Student ID kisi aur ke paas hai.")
    return render_template("student_form.html", student=st, mode="Edit")

@app.route("/admin/students/<int:sid>/status", methods=["POST"])
@admin_required
def student_status(sid):
    with db() as con:
        row=con.execute("SELECT u.id,u.active,s.student_no FROM students s JOIN users u ON u.id=s.user_id WHERE s.id=?", (sid,)).fetchone()
        if not row: abort(404)
        if row["id"]==session["uid"]: flash("Apna admin account disable nahi kar sakte.")
        else:
            con.execute("UPDATE users SET active=? WHERE id=?", (0 if row["active"] else 1,row["id"]))
            audit(session["username"],"ACCOUNT STATUS CHANGED",row["student_no"])
            flash("Student account status change ho gaya.")
    return redirect(url_for("student_list"))

@app.route("/admin/students/<int:sid>/marks", methods=["GET","POST"])
@admin_required
def manage_marks(sid):
    with db() as con:
        st=con.execute("SELECT * FROM students WHERE id=?", (sid,)).fetchone()
        if not st: abort(404)
        if request.method=="POST":
            subject=request.form.get("subject","").strip()
            try:
                total=int(request.form.get("total","0")); obtained=int(request.form.get("obtained","-1"))
                if not subject or total<=0 or obtained<0 or obtained>total: raise ValueError()
                con.execute("""INSERT INTO marks(student_id,subject,total,obtained,updated_at) VALUES(?,?,?,?,?)
                               ON CONFLICT(student_id,subject) DO UPDATE SET total=excluded.total,obtained=excluded.obtained,updated_at=excluded.updated_at""",
                            (sid,subject,total,obtained,now()))
                audit(session["username"],"MARKS ADDED/UPDATED",f"{st['student_no']} | {subject}: {obtained}/{total}")
                flash("Marks save ho gaye.")
            except (ValueError,sqlite3.IntegrityError): flash("Subject aur valid marks enter karein (obtained <= total).")
            return redirect(url_for("manage_marks",sid=sid))
        rows=con.execute("SELECT * FROM marks WHERE student_id=? ORDER BY subject", (sid,)).fetchall()
    return render_template("marks_admin.html", student=st, marks=rows)

@app.route("/admin/marks/<int:mid>/delete", methods=["POST"])
@admin_required
def delete_mark(mid):
    with db() as con:
        row=con.execute("SELECT m.subject,s.student_no FROM marks m JOIN students s ON s.id=m.student_id WHERE m.id=?", (mid,)).fetchone()
        if row:
            con.execute("DELETE FROM marks WHERE id=?", (mid,))
            audit(session["username"],"MARK DELETED",f"{row['student_no']} | {row['subject']}")
            flash("Subject marks delete ho gaye.")
    return redirect(request.referrer or url_for("student_list"))

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    with db() as con:
        st=con.execute("SELECT * FROM students WHERE user_id=?", (session["uid"],)).fetchone()
        if not st: abort(403)
        if request.method=="POST":
            f=request.form
            con.execute("UPDATE students SET full_name=?,email=?,phone=? WHERE user_id=?",
                        (f.get("full_name","").strip(),f.get("email","").strip(),f.get("phone","").strip(),session["uid"]))
            audit(session["username"],"PROFILE SELF-UPDATED","Name/email/phone")
            flash("Profile update ho gayi."); return redirect(url_for("profile"))
    return render_template("profile.html", student=st)

@app.route("/admin/logs")
@admin_required
def logs():
    with db() as con: rows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("logs.html", logs=rows)

@app.route("/admin/backup", methods=["GET","POST"])
@admin_required
def backup():
    path=os.path.join(BASE,"securecampus_backup.sqlite3")
    if request.method=="POST":
        with db() as con: con.execute("PRAGMA wal_checkpoint(FULL)")
        shutil.copy2(DB,path); audit(session["username"],"DATABASE BACKUP CREATED")
        flash("Backup create ho gaya.")
    return render_template("backup.html", exists=os.path.exists(path))

@app.errorhandler(403)
def forbidden(_): return render_template("error.html", code=403, message="Access denied — is section ke liye admin permission zaroori hai."),403
@app.errorhandler(404)
def missing(_): return render_template("error.html", code=404, message="Requested page ya record nahi mila."),404

if __name__=="__main__":
    init_db()
    print("SecureCampus Student Portal is starting...")
    app.run(host="127.0.0.1",port=5000,debug=False)
