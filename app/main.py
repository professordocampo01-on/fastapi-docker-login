# app/main.py
import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from databases import Database
from passlib.context import CryptContext
from jose import jwt

DATABASE_URL = "postgresql+asyncpg://postgres:postgres@db:5432/appdb"
SECRET_KEY = "supersecretkey"

app = FastAPI(title="FastAPI Docker Login")

db = Database(DATABASE_URL)

# Configuração do hash seguro com truncagem (para evitar erro > 72 bytes)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _truncate_password(pw: str, max_bytes: int = 72) -> str:
    """
    Trunca a senha para no máximo `max_bytes` bytes em UTF-8,
    retornando uma string válida (descartando qualquer byte incompleto no final).
    Isso evita o ValueError do bcrypt.
    """
    b = pw.encode("utf-8")
    if len(b) <= max_bytes:
        return pw
    return b[:max_bytes].decode("utf-8", errors="ignore")


class User(BaseModel):
    email: str
    password: str


@app.on_event("startup")
async def startup():
    """
    Tenta conectar ao banco com retries até que esteja pronto.
    Cria a tabela 'users' caso não exista.
    """
    max_attempts = 30
    delay_seconds = 1
    for attempt in range(1, max_attempts + 1):
        try:
            await db.connect()
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                );
                """
            )
            print("✅ Connected to database.")
            return
        except Exception as e:
            print(f"Database not ready (attempt {attempt}/{max_attempts}): {e}")
            if attempt == max_attempts:
                print("🚨 Máximo de tentativas atingido — abortando startup.")
                raise
            await asyncio.sleep(delay_seconds)


@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()


@app.post("/signup")
async def signup(user: User):
    query = "SELECT * FROM users WHERE email = :email"
    existing = await db.fetch_one(query, {"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Usuário já existe")

    # Usa a função de truncagem antes de gerar o hash
    pw_to_hash = _truncate_password(user.password)
    hashed = pwd_context.hash(pw_to_hash)

    await db.execute(
        "INSERT INTO users (email, password) VALUES (:email, :password)",
        {"email": user.email, "password": hashed},
    )
    return {"message": "Usuário cadastrado com sucesso"}


@app.post("/login")
async def login(user: User):
    query = "SELECT * FROM users WHERE email = :email"
    db_user = await db.fetch_one(query, {"email": user.email})
    # Usa truncagem também na verificação
    if not db_user or not pwd_context.verify(_truncate_password(user.password), db_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = jwt.encode({"email": user.email}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}
