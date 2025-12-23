from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory

import sqlite3
import datetime
from functools import wraps
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
import ssl
from email.mime.text import MIMEText
from flask import send_from_directory
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
    template_folder=str(BASE_DIR / "templates")
)

@app.route("/debug-static")
def debug_static():
    static_dir = BASE_DIR / "static"
    files = []
    if static_dir.exists():
        files = sorted([p.name for p in static_dir.iterdir() if p.is_file()])
    return {
        "BASE_DIR": str(BASE_DIR),
        "static_dir": str(static_dir),
        "static_exists": static_dir.exists(),
        "files": files
    }

@app.route("/ping")
def ping():
    return "PING OK"

@app.route("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(BASE_DIR / "static", filename)

app.config["SECRET_KEY"] = "dev-change-moi"  # change-le si tu veux
app.config["DATABASE"] = "data.db"

# ---------- CONFIG MAIL (GMAIL) ----------
app.config["MAIL_SENDER"] = "askly.noreply@gmail.com"      # ton mail Askly
app.config["SMTP_SERVER"] = "smtp.gmail.com"
app.config["SMTP_PORT"] = 587
app.config["SMTP_USERNAME"] = "askly.noreply@gmail.com"
app.config["SMTP_PASSWORD"] = "bxjv zcjm nuxi vira"

bcrypt = Bcrypt(app)

# ---------- DB ----------

def get_db():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn

# ---------- AUTH HELPERS ----------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Vous devez être connecté.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def get_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])

def generate_token(email, purpose):
    s = get_serializer()
    return s.dumps({"email": email, "purpose": purpose})

def load_token(token, max_age=3600):
    s = get_serializer()
    try:
        data = s.loads(token, max_age=max_age)
        return data
    except (BadSignature, SignatureExpired):
        return None

def send_email(dest, subject, body):
    """Envoie un vrai mail via Gmail. Si ça rate, on affiche tout dans la console."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = app.config["MAIL_SENDER"]
    msg["To"] = dest

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(app.config["SMTP_SERVER"], app.config["SMTP_PORT"]) as server:
            server.starttls(context=context)
            server.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
            server.send_message(msg)
        print(f"[MAIL] Envoyé à {dest} : {subject}")
    except Exception as e:
        print("=== ERREUR ENVOI MAIL ===")
        print("Erreur :", e)
        print("À :", dest)
        print("Sujet :", subject)
        print(body)
        print("=========================")

def infer_role_from_email(email: str) -> str:
    """Détermine le rôle à partir du domaine de l'email."""
    email = email.lower()
    if email.endswith("@ejm.org"):
        return "eleve"
    if email.endswith("@ejm.net"):
        return "prof"
    # sinon on force élève
    return "eleve"

# ---------- ROUTES DE BASE ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

# ---------- INSCRIPTION / LOGIN / LOGOUT ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nom = request.form["nom"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if not nom or not email or not password or not confirm:
            flash("Tous les champs sont obligatoires.")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.")
            return redirect(url_for("register"))

        if not (email.endswith("@ejm.org") or email.endswith("@ejm.net")):
            flash("Utilise ton adresse scolaire (ejm.org pour élèves, ejm.net pour profs).")
            return redirect(url_for("register"))

        role = infer_role_from_email(email)
        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        now = datetime.datetime.now().isoformat()

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO user (nom, email, mot_de_passe_hash, role, date_inscription, email_verifie) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (nom, email, pw_hash, role, now),
            )
            conn.commit()
        except Exception as e:
            print("Erreur d'inscription:", e)
            flash("Email déjà utilisé.")
            return redirect(url_for("register"))

        token = generate_token(email, "verify")
        verify_url = url_for("verify_email", token=token, _external=True)
        body = (
            f"Bonjour {nom},\n\n"
            f"Bienvenue sur Askly !\n\n"
            f"Pour activer ton compte, clique sur ce lien :\n{verify_url}\n\n"
            f"Si tu n'es pas à l'origine de cette inscription, ignore ce message."
        )
        send_email(email, "Askly – Vérifie ton adresse email", body)

        flash("Compte créé. Vérifie tes mails pour activer ton compte.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/verify/<token>")
def verify_email(token):
    data = load_token(token, max_age=48 * 3600)
    if not data or data.get("purpose") != "verify":
        flash("Lien de vérification invalide ou expiré.")
        return redirect(url_for("index"))

    email = data["email"]
    conn = get_db()
    conn.execute("UPDATE user SET email_verifie = 1 WHERE email = ?", (email,))
    conn.commit()
    flash("Email vérifié, tu peux maintenant te connecter.")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]

        conn = get_db()
        cur = conn.execute("SELECT * FROM user WHERE email = ?", (email,))
        user = cur.fetchone()
        if user and bcrypt.check_password_hash(user["mot_de_passe_hash"], password):
            if not user["email_verifie"]:
                flash("Avant de te connecter, clique sur le lien reçu par mail pour vérifier ton adresse.")
                return redirect(url_for("login"))
            session["user_id"] = user["id"]
            session["user_role"] = user["role"]
            session["user_nom"] = user["nom"]
            flash("Connexion réussie.")
            return redirect(url_for("list_questions"))
        else:
            flash("Identifiants incorrects.")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnecté.")
    return redirect(url_for("index"))

# ---------- RESET MOT DE PASSE ----------

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password_request():
    if request.method == "POST":
        email = request.form["email"].strip()
        conn = get_db()
        cur = conn.execute("SELECT * FROM user WHERE email = ?", (email,))
        user = cur.fetchone()

        if user:
            token = generate_token(email, "reset")
            reset_url = url_for("reset_password", token=token, _external=True)
            body = (
                f"Bonjour,\n\n"
                f"Pour changer ton mot de passe Askly, clique sur ce lien :\n{reset_url}\n\n"
                f"Si tu n'as pas demandé de changement de mot de passe, ignore ce mail."
            )
            send_email(email, "Askly – Réinitialisation du mot de passe", body)

        flash("Si un compte existe pour cet email, un lien de réinitialisation a été envoyé.")
        return redirect(url_for("login"))

    return render_template("reset_password_request.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = load_token(token, max_age=2 * 3600)
    if not data or data.get("purpose") != "reset":
        flash("Lien de réinitialisation invalide ou expiré.")
        return redirect(url_for("login"))

    email = data["email"]
    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm_password"]
        if not password or not confirm:
            flash("Tous les champs sont obligatoires.")
            return redirect(url_for("reset_password", token=token))
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.")
            return redirect(url_for("reset_password", token=token))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        conn = get_db()
        conn.execute(
            "UPDATE user SET mot_de_passe_hash = ? WHERE email = ?",
            (pw_hash, email),
        )
        conn.commit()
        flash("Mot de passe mis à jour, tu peux te connecter.")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ---------- PROFIL UTILISATEUR ----------

@app.route("/profil", methods=["GET", "POST"])
@login_required
def profil():
    conn = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        nom = request.form["nom"].strip()
        if not nom:
            flash("Le nom ne peut pas être vide.")
            return redirect(url_for("profil"))
        conn.execute("UPDATE user SET nom = ? WHERE id = ?", (nom, user_id))
        conn.commit()
        session["user_nom"] = nom
        flash("Profil mis à jour.")
        return redirect(url_for("profil"))

    cur = conn.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cur.fetchone()

    cur_q = conn.execute(
        "SELECT COUNT(*) AS nb FROM question WHERE auteur_id = ?",
        (user_id,),
    )
    nb_q = cur_q.fetchone()["nb"]

    cur_r = conn.execute(
        "SELECT COUNT(*) AS nb FROM reponse WHERE auteur_id = ?",
        (user_id,),
    )
    nb_r = cur_r.fetchone()["nb"]

    cur_r_val = conn.execute(
        "SELECT COUNT(*) AS nb FROM reponse WHERE auteur_id = ? AND est_validee_par_prof = 1",
        (user_id,),
    )
    nb_r_val = cur_r_val.fetchone()["nb"]

    stats = {
        "questions_posees": nb_q,
        "reponses_donnees": nb_r,
        "reponses_validees": nb_r_val,
    }

    return render_template("profil.html", user=user, stats=stats)

# ---------- QUESTIONS / RÉPONSES ----------

@app.route("/questions")
def list_questions():
    search = request.args.get("search", "").strip()
    matiere = request.args.get("matiere", "").strip()

    query = (
        "SELECT q.id, q.titre, q.matiere, q.date_creation, q.statut, "
        "u.nom AS auteur_nom, q.auteur_id "
        "FROM question q JOIN user u ON q.auteur_id = u.id "
        "WHERE 1=1 "
    )
    params = []

    if search:
        query += "AND (q.titre LIKE ? OR q.contenu LIKE ?) "
        like = f"%{search}%"
        params.extend([like, like])

    if matiere:
        query += "AND q.matiere = ? "
        params.append(matiere)

    query += "ORDER BY q.date_creation DESC"

    conn = get_db()
    cur = conn.execute(query, params)
    questions = cur.fetchall()
    return render_template(
        "questions.html",
        questions=questions,
        search=search,
        matiere=matiere,
    )

@app.route("/questions/nouvelle", methods=["GET", "POST"])
@login_required
def new_question():
    if request.method == "POST":
        titre = request.form["titre"].strip()
        contenu = request.form["contenu"].strip()
        matiere = request.form.get("matiere", "").strip()
        auteur_id = session["user_id"]
        now = datetime.datetime.now().isoformat()

        if not titre or not contenu:
            flash("Titre et contenu obligatoires.")
            return redirect(url_for("new_question"))

        conn = get_db()
        conn.execute(
            "INSERT INTO question (titre, contenu, auteur_id, matiere, date_creation, statut) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (titre, contenu, auteur_id, matiere, now, "ouverte"),
        )
        conn.commit()
        flash("Question publiée.")
        return redirect(url_for("list_questions"))

    matieres = [
        "Maths", "Physique-Chimie", "NSI",
        "SVT", "Français", "Histoire-Géo", "Anglais",
        "HLP", "AP lang", "AP lit", "AP european history",
        "SES", "AP calculus", "Connaissance du Monde", "EMC",
        "AP human geography", "Philosophie", "Spe Art",
        "Musique", "Art"
    ]
    return render_template("new_question.html", matieres=matieres)

@app.route("/questions/<int:question_id>")
def question_detail(question_id):
    conn = get_db()
    cur_q = conn.execute(
        "SELECT q.*, u.nom AS auteur_nom FROM question q "
        "JOIN user u ON q.auteur_id = u.id WHERE q.id = ?",
        (question_id,),
    )
    question = cur_q.fetchone()
    if question is None:
        return "Question introuvable", 404

    cur_r = conn.execute(
        "SELECT r.*, u.nom AS auteur_nom FROM reponse r "
        "JOIN user u ON r.auteur_id = u.id "
        "WHERE r.question_id = ? "
        "ORDER BY r.date_creation ASC",
        (question_id,),
    )
    reponses = cur_r.fetchall()

    return render_template(
        "question_detail.html",
        question=question,
        reponses=reponses,
    )

@app.route("/questions/<int:question_id>/repondre", methods=["POST"])
@login_required
def answer_question(question_id):
    contenu = request.form["contenu"].strip()
    if not contenu:
        flash("La réponse ne peut pas être vide.")
        return redirect(url_for("question_detail", question_id=question_id))

    auteur_id = session["user_id"]
    now = datetime.datetime.now().isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO reponse (contenu, auteur_id, question_id, date_creation) "
        "VALUES (?, ?, ?, ?)",
        (contenu, auteur_id, question_id, now),
    )
    conn.commit()
    flash("Réponse ajoutée.")
    return redirect(url_for("question_detail", question_id=question_id))

@app.route("/reponses/<int:reponse_id>/valider", methods=["POST"])
@login_required
def valider_reponse(reponse_id):
    if session.get("user_role") != "prof":
        flash("Seuls les profs peuvent valider une réponse.")
        return redirect(url_for("list_questions"))

    conn = get_db()
    cur = conn.execute(
        "SELECT question_id FROM reponse WHERE id = ?",
        (reponse_id,),
    )
    rep = cur.fetchone()
    if rep is None:
        flash("Réponse introuvable.")
        return redirect(url_for("list_questions"))

    question_id = rep["question_id"]

    conn.execute(
        "UPDATE reponse SET est_validee_par_prof = 1 WHERE id = ?",
        (reponse_id,),
    )
    conn.execute(
        "UPDATE question SET statut = 'resolue' WHERE id = ?",
        (question_id,),
    )
    conn.commit()
    flash("Réponse validée, question résolue.")
    return redirect(url_for("question_detail", question_id=question_id))

# ---------- SUPPRESSION (auteur ou admin) ----------

@app.route("/questions/<int:question_id>/supprimer", methods=["POST"])
@login_required
def delete_question(question_id):
    conn = get_db()
    cur = conn.execute(
        "SELECT auteur_id FROM question WHERE id = ?",
        (question_id,),
    )
    q = cur.fetchone()
    if q is None:
        flash("Question introuvable.")
        return redirect(url_for("list_questions"))

    user_id = session.get("user_id")
    role = session.get("user_role")
    if role != "admin" and user_id != q["auteur_id"]:
        flash("Tu ne peux supprimer que tes propres questions.")
        return redirect(url_for("question_detail", question_id=question_id))

    conn.execute("DELETE FROM reponse WHERE question_id = ?", (question_id,))
    conn.execute("DELETE FROM question WHERE id = ?", (question_id,))
    conn.commit()
    flash("Question supprimée.")
    return redirect(url_for("list_questions"))

@app.route("/reponses/<int:reponse_id>/supprimer", methods=["POST"])
@login_required
def delete_reponse(reponse_id):
    conn = get_db()
    cur = conn.execute(
        "SELECT auteur_id, question_id FROM reponse WHERE id = ?",
        (reponse_id,),
    )
    r = cur.fetchone()
    if r is None:
        flash("Réponse introuvable.")
        return redirect(url_for("list_questions"))

    user_id = session.get("user_id")
    role = session.get("user_role")
    if role != "admin" and user_id != r["auteur_id"]:
        flash("Tu ne peux supprimer que tes propres réponses.")
        return redirect(url_for("question_detail", question_id=r["question_id"]))

    conn.execute("DELETE FROM reponse WHERE id = ?", (reponse_id,))
    conn.commit()
    flash("Réponse supprimée.")
    return redirect(url_for("question_detail", question_id=r["question_id"]))

# ---------- MAIN ----------

if __name__ == "__main__":
    app.run()

