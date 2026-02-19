import sqlite3
from datetime import datetime


def conectar_db():
    con = sqlite3.connect("users.db")
    return con


# email é UNIQUE porque só pode existir uma vez
def criar_tabela_utilizadores_db():
    with sqlite3.connect("users.db") as con:
        cursor = con.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL
        )
        """)
        con.commit()


# Aqui apenas recebemos o email e password_hash como argumentos porque sao os unicos dados que vem de fora(do endpoint)
# o created_at e is_active sao definidos automaticamente porque fazem parte da lógica da db e nao devem ser decididos pelo endpoint
def inserir_utilizadores_db(email, password_hash):
    with sqlite3.connect("users.db") as con:
        cursor = con.cursor()
        cursor.execute("""INSERT INTO users(
        email, password_hash, created_at, is_active) 
        VALUES(?, ?, ?, ?)""", (email, password_hash, datetime.now().isoformat(), 1))
        con.commit()



def listar_utilizador_db(email):
    with sqlite3.connect("users.db") as con:
        cursor = con.cursor()
        cursor.execute("SELECT email, password_hash FROM users WHERE email = ?", (email,))
    linha = cursor.fetchone()
    return linha
