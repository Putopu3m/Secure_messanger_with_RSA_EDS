import os
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from sqlalchemy.orm import Session
import asyncio

from .models import TelegramCode, User
from .db import SessionLocal
from .security import generate_tg_code, hash_code_sha256
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


@dp.message(Command("start"))
async def start(message: types.Message):
    username = message.from_user.username  # "alice"
    chat_id = message.chat.id              # 123456789

    if not username:
        await message.answer("У вас не установлен username в Telegram, задайте его в настройках.")
        return

    # сохраняем в БД
    db: Session = SessionLocal()
    user = db.query(User).filter_by(telegram_username=username).first()
    if user:
        user.chat_id = chat_id
        db.commit()
        await message.answer("Ваш аккаунт привязан, теперь бот может отправлять вам коды.")
    else:
        await message.answer("Пользователь с таким username не зарегистрирован.")
    db.close()


async def send_code(username: str):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter_by(telegram_username=username).first()
        if not user:
            raise ValueError(f"User {username} not found")

        code = generate_tg_code()
        code_hash = hash_code_sha256(code)

        if user.tg_code:
            db.delete(user.tg_code)
            db.commit()

        # создаём запись в БД
        tg_code = TelegramCode(code=code_hash, user=user)
        db.add(tg_code)
        db.commit()
        db.refresh(tg_code)
        
        await bot.send_message(
            chat_id=user.chat_id,
            text=f"Ваш код для входа: {code}\nОн будет действителен 2 минуты."
        )

        return tg_code
    finally:
        db.close()


async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
