import secrets

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from . import db, models, schemas, security

app = FastAPI()

models.Base.metadata.create_all(bind=db.engine)


challenges = {}


@app.post("/challenge")
async def challenge(
    challenge_request: schemas.ChallengeRequest,
    db_session: Session = Depends(db.get_db),
):
    # Проверка существования пользователя
    user = (
        db_session.query(models.User)
        .filter_by(username=challenge_request.username)
        .first()
    )
    # Если пользователь не найден, возвращаем ошибку
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Генерация и сохранение challenge
    challenge = secrets.token_hex(16)
    challenges[challenge_request.username] = challenge

    # Хеширование challenge для отправки клиенту
    challenge_hash = security.hash_code_sha256(challenge)
    return {"challenge_hash": challenge_hash}


@app.post("/authenticate")
async def authenticate(
    auth_request: schemas.AuthRequest, db_session: Session = Depends(db.get_db)
):
    # Проверка существования пользователя
    user = (
        db_session.query(models.User).filter_by(username=auth_request.username).first()
    )

    # Если пользователь не найден, возвращаем ошибку
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Проверка наличия challenge
    challenge = challenges.get(auth_request.username)
    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found for user")

    # Хеширование challenge для проверки
    challenge_hash = security.hash_code_sha256(challenge)

    # Проверка ответа клиента
    expected_response = security.hash_code_sha256(user.password_sha256 + challenge_hash)

    # Если хеши не совпадают, возвращаем ошибку
    if expected_response != auth_request.response_hash:
        raise HTTPException(status_code=401, detail="Authentication failed")

    # Удаляем challenge после успешной аутентификации
    del challenges[auth_request.username]

    return {"status": "ok", "message": "Authenticated successfully"}


@app.post("/register", response_model=schemas.RegisterResponse)
async def register(
    user: schemas.RegisterRequest, db_session: Session = Depends(db.get_db)
):
    # Проверка существования пользователя
    existing = db_session.query(models.User).filter_by(username=user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    # Хеширование пароля и генерация кода для Telegram
    bcrypt_hash = security.hash_password_bcrypt(user.password)
    sha256_hash = security.hash_password_sha256(user.password)

    tg_code = security.generate_tg_code()
    tg_code_hash = security.hash_code_sha256(tg_code)

    # Создание пользователя в базе данных
    new_user = models.User(
        username=user.username,
        password_bcrypt=bcrypt_hash,
        password_sha256=sha256_hash,
        telegram_username=user.telegram_username,
        tg_code_hash=tg_code_hash,
    )
    db_session.add(new_user)
    db_session.commit()

    # Отправка кода в телеграм
    # asyncio.create_task(telegram_bot.send_tg_code(new_user.telegram_username, tg_code))

    return {"status": "ok", "message": "User registered, code sent to Telegram"}
