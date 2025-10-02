import hashlib

import httpx
from fastapi import FastAPI, HTTPException

from . import schemas

app = FastAPI()

BASE_CLIENT_URL = "http://localhost:8000"


@app.post("/login")
async def login(login_request: schemas.LoginRequest):
    # Хеширование пароля для аутентификации
    password_sha256 = hashlib.sha256(login_request.password.encode()).hexdigest()

    # Получение challenge от сервера
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/challenge",
            json={
                "username": login_request.username,
            },
        )

    # Если сервер вернул ошибку, пробрасываем её клиенту
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Login failed")

    # Формирование ответа на challenge
    challenge_hash = response.json().get("challenge_hash")
    response = hashlib.sha256((password_sha256 + challenge_hash).encode()).hexdigest()

    # Отправка ответа на challenge для аутентификации
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/authenticate",
            json={"username": login_request.username, "response_hash": response},
        )

    # Если сервер вернул ошибку, пробрасываем её клиенту
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Login failed")

    # Возвращаем ответ сервера клиенту
    return response.json()
