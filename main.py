import sqlite3
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr  # Basemodel = base de dados dos shemas//EmailStr = valida emails reais
from database import inserir_utilizadores_db
from database import criar_tabela_utilizadores_db
from database import listar_utilizador_db
from security import hash_password
from security import verificar_password
from security import criar_token_acesso
from security import verificar_token

app = FastAPI()

security = HTTPBearer(auto_error=True)

# temos de chamar esta def do database ao iniciar a app para criar a tabela
criar_tabela_utilizadores_db()


# ----------------SCHEMAS------------------------
# Esta classe serve apenas para dizer a API que dados sao necessarios para criar um utilizador.
# Nao è uma classe normal com init, pois eu nao crio objetos manualmente.
# O FastApi cria o objeto automaticamente quando recebe um JSON do cliente.
class CriarUsuario(BaseModel):
    email: EmailStr  # verifica automaticamente se o email é valido
    password: str  # password em texto simples


class LoginUsuario(BaseModel):
    email: EmailStr
    password: str


# -----------------ENDPOINTS--------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# Endpoint para registo de utilizadores
# Quando alguém faz um POST para /register:
# 1. O FastAPI lê o JSON enviado no body
# 2. Valida os dados usando o schema CriarUsuario
# 3. Cria automaticamente o objeto 'user'
# 4. Executa esta função
@app.post("/register")
def register(user: CriarUsuario):  # por boas práticas nao devolvemos a password na resposta, so o email

    # transformamos a password em hash seguro
    password_hash = hash_password(user.password)

    # validacao para impedir registar o mesmo email(cada email é unico)
    try:
        # Guardamos o utilizador na base de dados
        inserir_utilizadores_db(user.email, password_hash)

    except sqlite3.IntegrityError:
        # Usamos o erro http 409 porque o pedido está correto, mas entra em conflito com dados ja existentes no sistema
        raise HTTPException(status_code=409, detail="Este email já está registado")

    return {
        "email": user.email,
        "message": "Utilizador registado com sucesso"
    }


# Endpoint para login de utilizadores
@app.post("/login")
def login(user: LoginUsuario):
    # chamamos a def da db com o argumento user.email
    buscar_utilizador = listar_utilizador_db(user.email)
    if buscar_utilizador is None:
        # usamos o erro 401 porque é um erro de autenticação
        raise HTTPException(status_code=401, detail="Email ou password inválidos")

    # extraimos a password que esta no indice 1
    password_hash = buscar_utilizador[1]

    # verificamos se a password enviada corresponde ao hash guardado
    if not verificar_password(user.password, password_hash):
        raise HTTPException(status_code=401, detail="Email ou password inválidos")

    # Criamos um dicionário(preparamos os dados que vão dentro to ‘token’ // 'sub' significa subject(dono to token)
    dados_token = {"sub": user.email}

    #
    token = criar_token_acesso(dados_token)

    # Devolvemos o JWT gerado após autenticação bem-sucedida.
    # A API é stateless, ou seja, não guarda sessão.
    # Em vez disso o cliente recebe um ‘token’ que prova a sua identidade
    # 'bearer' é o portador do ‘token’
    return {
        "access_token": token,
        "token_type": "bearer"
    }


# Este endpoint só pode ser usado por um utilizador autenticado.
# A parte "credentials = Depends(security)" significa:
# Antes de executar esta função, o FastAPI vai verificar
# se o cliente enviou um ‘token’ no header "Authorization".
# O cliente deve enviar algo assim:
# Authorization: Bearer <token>
# Se o header não existir ou estiver mal escrito,
# o FastAPI devolve automaticamente erro 401
# e a função nem chega a ser executada.
# Se estiver correto, o FastAPI cria automaticamente
# um objeto chamado "credentials" que contém:
#   credentials.scheme - normalmente "Bearer"
#   credentials.credentials - o ‘token’ real (JWT)
# Ou seja, não precisamos verificar manualmente se começa
# com "Bearer" nem dividir a ‘string’.
# O FastAPI já faz essa isso por mim
# Isto deixa o código mais simples, mais seguro
# e evita repetir validações em vários endpoints.
@app.get("/me")  # HTTPAuthorizationCredentials = estrutura que contem o token // Depends(security) = exige o token
def me(credentials: HTTPAuthorizationCredentials = Depends(security)):

    # O objeto "credentials" foi criado automaticamente pelo HTTPBearer.
    # Ele já separou o header "Authorization" em duas partes:
    #   scheme - normalmente "Bearer"
    #   credentials - o ‘token’ JWT verdadeiro
    # Aqui guardamos apenas o ‘token’ puro numa variável chamada "token" para depois o validar
    token = credentials.credentials

    # vamos buscar o payload(conteudo interno do JWT ja validado) á def verificar_token, a security.py
    # exemplo: "sub": "marco@mail.com, "exp": 17000000
    payload = verificar_token(token)

    # buscamos o email que representa o utilizador autenticado
    email = payload["sub"]

    # vamos buscar o utilizador à db atraves do seu email extraido do ‘token’
    utilizador = listar_utilizador_db(email)
    # se o utilizador não existir lancamos uma exceção 404
    if not utilizador:
        raise HTTPException(status_code=404, detail="Utilizador não encontrado")

    # retornamos o email do utilizador
    return {"email": email}

