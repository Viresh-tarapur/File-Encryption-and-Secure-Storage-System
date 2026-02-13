from flask import Flask, render_template, request, redirect, session, flash, send_file
import mysql.connector
from cryptography.fernet import Fernet
import io, os, re

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret")

# ---------------- DATABASE ----------------
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT", 3306))
    )

# ---------------- ENCRYPTION ----------------
if not os.path.exists("secret.key"):
    open("secret.key","wb").write(Fernet.generate_key())

cipher = Fernet(open("secret.key","rb").read())

# ---------------- PASSWORD RULE ----------------
def strong_pw(pw):
    return len(pw)>=8 and re.search("[A-Z]",pw) and re.search("[a-z]",pw) \
           and re.search("[0-9]",pw) and re.search("[!@#$%^&*]",pw)

# ---------------- HOME ----------------
@app.route("/")
def home():
    uid=session.get("user_id",0)
    files=[]
    if uid:
        db=get_db()
        cur=db.cursor()
        cur.execute("SELECT id,file_name FROM files WHERE user_id=%s",(uid,))
        files=cur.fetchall()
        db.close()
    return render_template("index.html",user_id=uid,files=files)

# ---------------- SIGNUP ----------------
@app.route("/signup",methods=["POST"])
def signup():
    email=request.form["email"]
    password=request.form["password"]

    if not strong_pw(password):
        flash("Weak Password")
        return redirect("/")

    try:
        db=get_db()
        cur=db.cursor()
        cur.execute("INSERT INTO users(email,password) VALUES(%s,%s)",(email,password))
        db.commit()
        db.close()
        flash("Signup Success")
    except:
        flash("User Exists")

    return redirect("/")

# ---------------- LOGIN ----------------
@app.route("/login",methods=["POST"])
def login():
    email=request.form["email"]

    db=get_db()
    cur=db.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s",(email,))
    user=cur.fetchone()
    db.close()

    if user:
        session["user_id"]=user[0]
        flash("Login Success")
    else:
        flash("Email Not Found")

    return redirect("/")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- UPLOAD ----------------
@app.route("/upload",methods=["POST"])
def upload():
    if "user_id" not in session:
        flash("Login Required")
        return redirect("/")

    file=request.files["file"]
    if file.filename=="":
        flash("No File")
        return redirect("/")

    enc=cipher.encrypt(file.read())

    db=get_db()
    cur=db.cursor()
    cur.execute("INSERT INTO files(user_id,file_name,encrypted_data) VALUES(%s,%s,%s)",
                (session["user_id"],file.filename,enc))
    db.commit()
    db.close()

    flash("Uploaded")
    return redirect("/")

# ---------------- ASK PASSWORD FOR VIEW ----------------
@app.route("/ask/<int:file_id>")
def ask(file_id):
    uid=session["user_id"]
    db=get_db()
    cur=db.cursor()
    cur.execute("SELECT id,file_name FROM files WHERE user_id=%s",(uid,))
    files=cur.fetchall()
    db.close()
    return render_template("index.html",user_id=uid,files=files,ask_id=file_id)

# ---------------- VIEW ----------------
@app.route("/view",methods=["POST"])
def view_file():
    file_id=request.form["file_id"]
    password=request.form["password"]
    uid=session["user_id"]

    db=get_db()
    cur=db.cursor()
    cur.execute("SELECT password FROM users WHERE id=%s",(uid,))
    if cur.fetchone()[0] != password:
        flash("Wrong Password")
        return redirect("/")

    cur.execute("SELECT file_name,encrypted_data FROM files WHERE id=%s",(file_id,))
    file=cur.fetchone()
    db.close()

    dec=cipher.decrypt(file[1])
    return send_file(io.BytesIO(dec),download_name=file[0],as_attachment=False)

# ---------------- DOWNLOAD ----------------
@app.route("/download",methods=["POST"])
def download_file():
    file_id=request.form["file_id"]
    password=request.form["password"]
    uid=session["user_id"]

    db=get_db()
    cur=db.cursor()
    cur.execute("SELECT password FROM users WHERE id=%s",(uid,))
    if cur.fetchone()[0] != password:
        flash("Wrong Password")
        return redirect("/")

    cur.execute("SELECT file_name,encrypted_data FROM files WHERE id=%s",(file_id,))
    file=cur.fetchone()
    db.close()

    dec=cipher.decrypt(file[1])
    return send_file(io.BytesIO(dec),download_name=file[0],as_attachment=True)

# ---------------- ASK DELETE PASSWORD ----------------
@app.route("/delete/<int:file_id>")
def ask_delete(file_id):
    uid=session["user_id"]
    db=get_db()
    cur=db.cursor()
    cur.execute("SELECT id,file_name FROM files WHERE user_id=%s",(uid,))
    files=cur.fetchall()
    db.close()

    return render_template("index.html",
                           user_id=uid,
                           files=files,
                           delete_id=file_id)

# ---------------- CONFIRM DELETE ----------------
@app.route("/confirm_delete",methods=["POST"])
def confirm_delete():
    file_id=request.form["file_id"]
    password=request.form["password"]
    uid=session["user_id"]

    db=get_db()
    cur=db.cursor()

    cur.execute("SELECT password FROM users WHERE id=%s",(uid,))
    if cur.fetchone()[0] != password:
        flash("Wrong Password")
        return redirect("/")

    cur.execute("DELETE FROM files WHERE id=%s AND user_id=%s",(file_id,uid))
    db.commit()
    db.close()

    flash("File Deleted")
    return redirect("/")

# ---------------- RUN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

