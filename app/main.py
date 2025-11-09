from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from databases import Database
from passlib.hash import bcrypt
from jose import jwt

DATABASE_URL = "postgresql+asyncpg://postgres:postgres@db:5432/appdb"
SECRET_KEY = "supersecretkey"

app = FastAPI(title="FastAPI Docker Login")

db = Database(DATABASE_URL)


class User(BaseModel):
    email: str
    password: str


@app.on_event("startup")
async def startup():
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


@app.on_event("shutdown")
async def shutdown():
    await db.disconnect()


@app.post("/signup")
async def signup(user: User):
    query = "SELECT * FROM users WHERE email = :email"
    existing = await db.fetch_one(query, {"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Usuário já existe")
    hashed = bcrypt.hash(user.password)
    await db.execute(
        "INSERT INTO users (email, password) VALUES (:email, :password)",
        {"email": user.email, "password": hashed},
    )
    return {"message": "Usuário cadastrado com sucesso"}


@app.post("/login")
async def login(user: User):
    query = "SELECT * FROM users WHERE email = :email"
    db_user = await db.fetch_one(query, {"email": user.email})
    if not db_user or not bcrypt.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    token = jwt.encode({"email": user.email}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}
