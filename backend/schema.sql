CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nom TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  mot_de_passe_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  date_inscription TEXT NOT NULL,
  email_verifie INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE question (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  titre TEXT NOT NULL,
  contenu TEXT NOT NULL,
  auteur_id INTEGER NOT NULL,
  matiere TEXT,
  date_creation TEXT NOT NULL,
  statut TEXT NOT NULL,
  FOREIGN KEY(auteur_id) REFERENCES user(id)
);

CREATE TABLE reponse (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contenu TEXT NOT NULL,
  auteur_id INTEGER NOT NULL,
  question_id INTEGER NOT NULL,
  date_creation TEXT NOT NULL,
  est_validee_par_prof INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(auteur_id) REFERENCES user(id),
  FOREIGN KEY(question_id) REFERENCES question(id)
);
