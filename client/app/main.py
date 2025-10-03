import hashlib

import httpx
from fastapi import FastAPI, HTTPException

from . import schemas

app = FastAPI()

BASE_CLIENT_URL = "http://localhost:8000"

session_data = {}


@app.post("/create_challenge")
async def create_challenge(challenge_request: schemas.ChallengeRequest):
    # Получение challenge от сервера
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/challenge",
            json={
                "username": challenge_request.username,
            },
        )

    # Если сервер вернул ошибку, пробрасываем её клиенту
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Login failed")

    # Сохраняем challenge_hash в сессии
    session_data[challenge_request.username] = response.json().get("challenge_hash")

    return {"message": "Challenge создан. Проверьте Telegram для кода."}


@app.post("/authenticate")
async def authenticate(login_request: schemas.LoginRequest):
    if login_request.username not in session_data:
        raise HTTPException(status_code=400, detail="No active challenge")
    
    challenge_hash = session_data.pop(login_request.username)
    password_sha256 = hashlib.sha256(login_request.password.encode()).hexdigest()
    code_sha256 = hashlib.sha256(login_request.tg_code.encode()).hexdigest()

    response = hashlib.sha256((password_sha256 + challenge_hash + code_sha256).encode()).hexdigest()

    # Отправка ответа на challenge для аутентификации
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/authenticate",
            json={
                "username": login_request.username,
                "response_hash": response
            },
        )

    # Если сервер вернул ошибку, пробрасываем её клиенту
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Login failed")

    # Возвращаем ответ сервера клиенту
    return response.json()
