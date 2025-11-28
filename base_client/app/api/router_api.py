import base64
import secrets
import json

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


session_data: dict[str, dict[str, str]] = {
    "aes_keys": {},  # user_id: aes_key
}


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
        telegram_username=user.telegram_username if user.telegram_username else None,
    )
    db_session.add(new_user)
    db_session.commit()

    return {"status": "ok", "message": "User registered, code sent to Telegram"}


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

    if user.telegram_username:
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

    if not challenge:
        print("Нет challenge")
        raise HTTPException(
            status_code=400, detail="No challenge found for user"
        )

    if security.is_code_expired(challenge.created_at):
        print("Код истёк")
        raise HTTPException(status_code=400, detail="Challenge has expired")

    challenge_hash = security.hash_sha256(challenge.challenge)


    expected_response = security.hash_sha256(
        user.password_sha256 + challenge_hash + (tg_code.code if tg_code else "")
    )

    if expected_response != auth_request.response_hash:
        print("Хеши не совпадают")
        raise HTTPException(status_code=401, detail="Authentication failed")

    db_session.delete(challenge)
    db_session.commit()

    session_data["user_id"] = user.id
    return {"status": "ok", "message": "Authenticated successfully", "user_id": user.id}


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
    session_data["aes_keys"][session_data["user_id"]] = base64.b64encode(shared_key).decode()
    print("Общий AES ключ:", session_data["aes_keys"][session_data["user_id"]])

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

    key = session_data["aes_keys"].get(user_id)
    if not key:
        raise HTTPException(status_code=404, detail="AES key not found")

    try:
        await router_ws.manager.broadcast_message_from_admin_to_user(
            user_id, request.text, key
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "ok"}


@router.post("/polls/create")
async def create_poll(req: base_client.app.schemas.CreatePollRequest, db: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db)):
    poll = base_client.app.models.Poll(topic=req.topic)
    db.add(poll)
    db.commit()
    db.refresh(poll)

    # Broadcast poll to all connected users (encrypted per user)
    # We'll send JSON: {"type":"poll","poll_id":id,"topic":topic, "m":..., "e":...}
    pub = security.get_center_public_rsa()  # should return (m,e) or serialized public key
    # prefer returning integers m,e
    m, e = pub["m"], pub["e"]
    obj = {"type":"poll", "poll_id": poll.id, "topic": poll.topic, "m": str(m), "e": str(e)}
    # send to all currently connected users (encrypt per-user with their aes key)
    for user_id, ws in list(router_ws.manager.user_connections.items()):
        key = session_data["aes_keys"].get(user_id)  # wrapper for router_api.session_data["aes_key"] per user
        if key:
            enc = security.aes_encrypt(json.dumps(obj), key)
            try:
                await ws.send_text(enc)
            except Exception:
                pass

    return {"status":"ok","poll_id":poll.id}


@router.post("/vote")
async def submit_vote(vote: base_client.app.schemas.VoteRequest, db: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db)):
    # save fi as string (client computed fi = pow(ti,e,m) -> large int)
    sub = base_client.app.models.VoteSubmission(poll_id=vote.poll_id, user_id=vote.user_id, fi=vote.fi)
    db.add(sub)
    db.commit()
    return {"status":"ok"}


@router.post("/polls/{poll_id}/tally")
async def tally_poll(poll_id: int, db: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db)):
    poll = db.query(base_client.app.models.Poll).filter_by(id=poll_id).first()
    if not poll:
        raise HTTPException(404, "Poll not found")

    subs = db.query(base_client.app.models.VoteSubmission).filter_by(poll_id=poll_id).all()
    if not subs:
        raise HTTPException(400, "No votes")

    # get center private key (m,d)
    center = security.get_center_private_rsa()  # expect dict {"m":m,"d":d}
    m = center["m"]
    d = center["d"]

    # compute product F = prod(fi) mod m
    F = 1
    for s in subs:
        fi_int = int(s.fi)
        F = (F * (fi_int % m)) % m

    # decrypt Q = F^d mod m
    Q = pow(F, d, m)

    # compute powers of 2 and 3 in Q
    tmp = Q
    r = 0
    while tmp % 2 == 0:
        r += 1
        tmp //= 2
    p = 0
    while tmp % 3 == 0:
        p += 1
        tmp //= 3
    R = tmp  # product of qi

    # mark poll closed
    poll.is_open = 0
    db.add(poll)
    db.commit()

    res = {"poll_id": poll_id, "for": r, "against": p, "abstain": len(subs) - (r+p), "R": str(R), "Q": str(Q), "F": str(F)}

    # broadcast results to admins and all users (admin gets plain JSON; users get encrypted)
    await router_ws.manager.broadcast_to_admins({"type":"poll_result", **res})
    for user_id, ws in list(router_ws.manager.user_connections.items()):
        key = session_data["aes_keys"].get(user_id)  # wrapper for router_api.session_data["aes_key"] per user
        if key:
            enc = security.aes_encrypt(json.dumps({"type":"poll_result", **res}), key)
            try:
                await ws.send_text(enc)
            except Exception:
                pass

    return res