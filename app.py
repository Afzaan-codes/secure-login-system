import os, sqlite3, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from argon2 import PasswordHasher
import pyotp

app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB="users.db"
ph=PasswordHasher()

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    c=db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        totp_secret TEXT)""")
    c.commit(); c.close()

def required(f):
    @wraps(f)
    def w(*a,**k):
        if "user_id" not in session: return redirect(url_for("login"))
        return f(*a,**k)
    return w

@app.route("/")
def home(): return render_template("index.html")

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        u=request.form.get("username","").strip()
        p=request.form.get("password","")
        if len(u)<3 or len(u)>30 or not u.replace("_","").isalnum():
            flash("Username must be 3-30 characters and use letters, numbers or _.")
        elif len(p)<8:
            flash("Password must be at least 8 characters.")
        else:
            c=db()
            try:
                c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",(u,ph.hash(p)))
                c.commit(); c.close()
                flash("Registration successful."); return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                c.close(); flash("Username already exists.")
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        c=db(); user=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone(); c.close()
        if user:
            try:
                ph.verify(user["password_hash"],p)
                if user["totp_secret"]:
                    session["pending"]=user["id"]; return redirect(url_for("verify_2fa"))
                session.clear(); session["user_id"]=user["id"]; session["username"]=user["username"]
                return redirect(url_for("dashboard"))
            except Exception: pass
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/verify-2fa",methods=["GET","POST"])
def verify_2fa():
    uid=session.get("pending")
    if not uid: return redirect(url_for("login"))
    c=db(); user=c.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone(); c.close()
    if request.method=="POST":
        code=request.form.get("code","").strip()
        if user and pyotp.TOTP(user["totp_secret"]).verify(code,valid_window=1):
            session.clear(); session["user_id"]=user["id"]; session["username"]=user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid 2FA code.")
    return render_template("verify_2fa.html")

@app.route("/setup-2fa",methods=["GET","POST"])
@required
def setup_2fa():
    c=db()
    if request.method=="POST":
        secret=pyotp.random_base32()
        c.execute("UPDATE users SET totp_secret=? WHERE id=?",(secret,session["user_id"]))
        c.commit(); c.close(); session["new_secret"]=secret
        return redirect(url_for("setup_2fa"))
    user=c.execute("SELECT username,totp_secret FROM users WHERE id=?",(session["user_id"],)).fetchone(); c.close()
    secret=session.get("new_secret") or user["totp_secret"]
    uri=pyotp.TOTP(secret).provisioning_uri(user["username"],issuer_name="Secure Login System") if secret else ""
    return render_template("setup_2fa.html",secret=secret,uri=uri)

@app.route("/dashboard")
@required
def dashboard(): return render_template("dashboard.html",username=session["username"])

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

if __name__=="__main__":
    init_db(); app.run(debug=True)
