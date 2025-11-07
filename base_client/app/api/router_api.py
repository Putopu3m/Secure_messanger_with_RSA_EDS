import base64
import secrets

import sqlalchemy.orm
from fastapi import APIRouter, Depends, HTTPException

import base_client.app.api.router_ws as router_ws
import base_client.app.db
import base_client.app.models
import base_client.app.schemas
import base_client.app.telegram_bot
from security import security

router = APIRouter()

base_client.app.models.Base.metadata.create_all(bind=base_client.app.db.engine)


session_data = {}


@router.post("/challenge")
async def challenge(
    challenge_request: base_client.app.schemas.ChallengeRequest,
    db_session: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db),
):
    user = (
        db_session.query(base_client.app.models.User)
        .filter_by(username=challenge_request.username)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    challenge = secrets.token_hex(16)

    if user.challenges:
        db_session.delete(user.challenges)
        db_session.commit()

    db_challenge = base_client.app.models.Challenge(
        user_id=user.id, challenge=challenge
    )
    db_session.add(db_challenge)
    db_session.commit()

    challenge_hash = security.hash_sha256(challenge)

    await base_client.app.telegram_bot.send_code(user.telegram_username)
    return {"challenge_hash": challenge_hash}


@router.post("/authenticate")
async def authenticate(
    auth_request: base_client.app.schemas.AuthRequest,
    db_session: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db),
):
    user = (
        db_session.query(base_client.app.models.User)
        .filter_by(username=auth_request.username)
        .first()
    )

    if not user:
        print("Пользователь не найден")
        raise HTTPException(status_code=404, detail="User not found")

    challenge = (
        db_session.query(base_client.app.models.Challenge)
        .filter_by(user_id=user.id)
        .order_by(base_client.app.models.Challenge.created_at.desc())
        .first()
    )
    tg_code = (
        db_session.query(base_client.app.models.TelegramCode)
        .filter_by(user_id=user.id)
        .order_by(base_client.app.models.TelegramCode.created_at.desc())
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

    return {"status": "ok", "message": "Authenticated successfully", "user_id": user.id}


@router.post("/register", response_model=base_client.app.schemas.RegisterResponse)
async def register(
    user: base_client.app.schemas.RegisterRequest,
    db_session: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db),
):
    existing = (
        db_session.query(base_client.app.models.User)
        .filter_by(username=user.username)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    bcrypt_hash = security.hash_bcrypt(user.password)
    sha256_hash = security.hash_sha256(user.password)

    new_user = base_client.app.models.User(
        username=user.username,
        password_bcrypt=bcrypt_hash,
        password_sha256=sha256_hash,
        telegram_username=user.telegram_username,
    )
    db_session.add(new_user)
    db_session.commit()

    return {"status": "ok", "message": "User registered, code sent to Telegram"}


@router.post("/dh/respond")
async def dh_respond(request: base_client.app.schemas.DHInitiateRequest):
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


@router.post("/send_to_user")
async def send_to_user(request: base_client.app.schemas.SendMessage):
    try:
        user_id = int(request.user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    key = session_data["aes_key"]
    if not key:
        raise HTTPException(status_code=404, detail="AES key not found")

    try:
        await router_ws.manager.broadcast_message_from_admin_to_user(user_id, request.text, key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "ok"}
