# Durante o desenvolvimento surgiu uma incompatibilidade entre passlib e bcrypt causando erros de hashing
# (mesmo com passwords pequenas). O problema foi resolvido com a recriação de um novo ambiente virtual e usando
# uma combinacao estavel e compativel das bibliotecas acima mencionadas(atencao as versoes usadas das bibliotecas)


from passlib.context import CryptContext
from jose import jwt  # geração e validação de tokens
from jose import JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException


# ----------------CONSTANTES---------------------------
# IMPORTANTE: Constantes sao configurações fixas do sistema e nao deveM ser alteradas durante execução
#    - ficam sempre no topo
#    - agrupadas
#    - são configurações globais
#    - não é para mexer no meio da lógica
#    - não é para redefinir dentro de funções
# Chave secreta usada para assinar ‘tokens’ e deve estar sempre numa variavel de ambiente, nao diretamente no codigo
# Gerada com secrets.token_hex(32) // Tenho de importar secrets para gerar um ‘token’, mas depois devo apagá-lo
SECRET_KEY = "70bcb800db5fa949dd54d025e1d96c207a8dc56829bd6898c29fbcf33064fa55"
# Algoritmo de assinatura do JWT
ALGORITHM = "HS256"
# Tempo de expiração do ‘token’ em minutos
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# ------------------------------------------------------------


# usamos o algoritmo bcrypt que gera um salt garantindo hashes diferentes mesmo para passwords iguais
# deprecated=auto prepara futuras actualizacoes
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# recebe password em texto e transforma em hash seguro para armazenamento
def hash_password(password):
    hash = pwd_context.hash(password)
    return hash


# aqui verificamos se a password corresponde a hash guardada usando 'verify' e devolve true ou false
def verificar_password(password, password_hash):
    return pwd_context.verify(password, password_hash)


# Recebe um dicionário com os dados que irao dentro do token(payload)
# 'data: dict' é simplesmente informativo nao é obrigatorio, mas ajuda na leitura e organizacao do codigo
# e usamos dict porque JWT(JAVA WEB TOKEN) espera um conjunto tipo chave:valor, tal como os dicionários
def criar_token_acesso(data: dict):

    # Criamos uma cópia dos dados recebidos para evitar modificar o dicionário original por questoes de efeitos colaterais
    to_encode = data.copy()

    # calculamos o tempo limite que o token tem para ser valido,apos esse periodo,ele expira automaticamente
    # Usamos UTC porque evita problemas de fuso horario
    duracao_token = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Adicionamos ao payload(informação que vai dentro do ‘token’) o campo "exp"(expiration time)
    # Este campo é usado automaticamente na validação do JMT
    # Quando a data ultrapassar este valor, o ‘token’ torna-se invalido
    to_encode.update({"exp": duracao_token})

    # Criamos o ‘token’ JMT assinando o payload com a secret_key
    # O algoritmo define como assinatura é gerada
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verificar_token(token: str):
    try:
        # jwt.decode valida automaticamente:
        #  - a assinatura usando a SECRET_KEY
        #  - o algoritmo utilizado
        #  - a data de expiracao("exp")
        # Se tudo estiver correto devolve o conteudo interno do ‘token’, ou seja, o payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except JWTError:
        # Se o ‘token’ for invalido alterado ou expirado lanca uma exceção(401 - não autorizado)
        raise HTTPException(status_code=401, detail="Token Inválido ou expirado")
