import asyncio

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from . import db, models, schemas, security, telegram_bot

app = FastAPI()

models.Base.metadata.create_all(bind=db.engine)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=schemas.RegisterResponse)
async def register(
    user: schemas.RegisterRequest, db_session: Session = Depends(db.get_db)
):
    existing = db_session.query(models.User).filter_by(username=user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    bcrypt_hash = security.hash_password_bcrypt(user.password)

    tg_code = security.generate_tg_code()
    tg_code_hash = security.hash_code_sha256(tg_code)

    new_user = models.User(
        username=user.username,
        password_bcrypt=bcrypt_hash,
        telegram_username=user.telegram_username,
        tg_code_hash=tg_code_hash,
    )
    db_session.add(new_user)
    db_session.commit()

    # Отправка кода в телеграм
    asyncio.create_task(telegram_bot.send_tg_code(new_user.telegram_username, tg_code))

    return {"status": "ok", "message": "User registered, code sent to Telegram"}
