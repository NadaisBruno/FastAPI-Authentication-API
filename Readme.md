# FastAPI Authentication API

Esta aplicação é uma REST API construída com FastAPI que permite a autenticação de utilizadores com registo, ‘login’,
hashing e proteção de endpoints com JSON WEB TOKEN.

## Funcionalidades

    - Criação de APIs REST com FastAPI
    - Autenticação com JWT
    - Hashing seguro de passwords com brypt
    - Proteção de endpoints com HTTPBearer
    - Integração com base dados SQLite

## Endpoints

    - POST /register - Registo de novos utilizadores na base de dados, em que a password enviada é convertida 
      automaticamente em hash seguro antes de ser armazenada.
    - POST /login - Autenticação de utilizadores registados. Se esse utilizador for válido, gera um token JWT com tempo de expiração.
    - GET /me - Endpoint protegido que valida o token JWT enviado do header Authorization.
      Se o token for válido, identifica o utilizador autenticado e devolve o seu email.

## Fluxo de Autenticação

    1. O utilizador regista-se através do endpoint '/register'.
       A password é convertida em hash antes de ser guardada.
    2. O utilizador autentica-se através do endpoint '/login'.
       Se as credenciais forem válidas, recebe um JWT com tempo de expiração.
    3. Para aceder ao endpoint protegido '/me', o utilizador deve enviar o token no header:
       Authorization: Bearer <token>
    4. O servidor valida o token e identifica o utilizador.

## Como usar

1 - Iniciar o servidor com o comando:

    uvicorn main:app --reload

2 - Abrir no navegador o endereço:

    http://127.0.0.1:8000/docs


## Tecnologias Utilizadas

    - Python >= 3.10
    - FastAPI
    - SQLite
    - Passlib (bcrypt)
    - python-jose
