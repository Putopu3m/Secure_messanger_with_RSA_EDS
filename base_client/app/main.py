import base64
import secrets

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from security import security

from . import db, models, schemas, telegram_bot

app = FastAPI()

models.Base.metadata.create_all(bind=db.engine)


challenges = {}
session_data = {}


@app.post("/challenge")
async def challenge(
    challenge_request: schemas.ChallengeRequest,
    db_session: Session = Depends(db.get_db),
):
    user = (
        db_session.query(models.User)
        .filter_by(username=challenge_request.username)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    challenge = secrets.token_hex(16)

    if user.challenges:
        db_session.delete(user.challenges)
        db_session.commit()

    db_challenge = models.Challenge(user_id=user.id, challenge=challenge)
    db_session.add(db_challenge)
    db_session.commit()

    challenge_hash = security.hash_sha256(challenge)

    await telegram_bot.send_code(user.telegram_username)
    return {"challenge_hash": challenge_hash}


@app.post("/authenticate")
async def authenticate(
    auth_request: schemas.AuthRequest, db_session: Session = Depends(db.get_db)
):
    user = (
        db_session.query(models.User).filter_by(username=auth_request.username).first()
    )

    if not user:
        print("Пользователь не найден")
        raise HTTPException(status_code=404, detail="User not found")

    challenge = (
        db_session.query(models.Challenge)
        .filter_by(user_id=user.id)
        .order_by(models.Challenge.created_at.desc())
        .first()
    )
    tg_code = (
        db_session.query(models.TelegramCode)
        .filter_by(user_id=user.id)
        .order_by(models.TelegramCode.created_at.desc())
        .first()
    )

    if not challenge or not tg_code:
        print("Нет challenge или кода")
        raise HTTPException(
            status_code=400, detail="No challenge or Telegram code found for user"
        )

    if security.is_code_expired(challenge.created_at):
        print("Код истёк")
        raise HTTPException(status_code=400, detail="Telegram code has expired")

    challenge_hash = security.hash_sha256(challenge.challenge)

    expected_response = security.hash_sha256(
        user.password_sha256 + challenge_hash + tg_code.code
    )

    if expected_response != auth_request.response_hash:
        print("Хеши не совпадают")
        raise HTTPException(status_code=401, detail="Authentication failed")

    db_session.delete(challenge)
    db_session.commit()

    return {"status": "ok", "message": "Authenticated successfully"}


@app.post("/register", response_model=schemas.RegisterResponse)
async def register(
    user: schemas.RegisterRequest, db_session: Session = Depends(db.get_db)
):
    existing = db_session.query(models.User).filter_by(username=user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    bcrypt_hash = security.hash_bcrypt(user.password)
    sha256_hash = security.hash_sha256(user.password)

    new_user = models.User(
        username=user.username,
        password_bcrypt=bcrypt_hash,
        password_sha256=sha256_hash,
        telegram_username=user.telegram_username,
    )
    db_session.add(new_user)
    db_session.commit()

    return {"status": "ok", "message": "User registered, code sent to Telegram"}


@app.post("/dh/respond")
async def dh_respond(request: schemas.DHInitiateRequest):
    p = int(request.p)
    g = int(request.g)
    A = int(request.A)
    signature = request.signature
    client_pub = security.load_public_key(request.client_rsa_pub)

    if not security.verify_signature(client_pub, f"{p}{g}{A}".encode(), signature):
        raise HTTPException(status_code=400, detail="Invalid RSA signature")

    b, B = security.generate_dh_keypair(p, g)
    rsa_priv, rsa_pub = security.generate_rsa_keypair()

    response_signature = security.sign_message(rsa_priv, f"{B}".encode())

    shared_key = security.compute_shared_secret(A, b, p)
    session_data["aes_key"] = base64.b64encode(shared_key).decode()
    print("Общий AES ключ:", session_data["aes_key"])

    return {
        "B": str(B),
        "signature": response_signature,
        "server_rsa_pub": security.serialize_public_key(rsa_pub),
    }
