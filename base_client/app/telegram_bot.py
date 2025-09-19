import os

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from . import db
from .models import TelegramUser

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = Bot(token=TELEGRAM_TOKEN)
dp = Dispatcher()


@dp.message(Command("start"))
async def register_user(message: types.Message, db: Session = next(db.get_db())):
    username = message.from_user.username
    chat_id = message.chat.id
    if not username:
        await message.answer("У вас нет username в Telegram. Задайте его в настройках.")
        return

    tg_user = db.query(TelegramUser).filter_by(telegram_username=username).first()
    if tg_user:
        tg_user.chat_id = str(chat_id)
    else:
        tg_user = TelegramUser(telegram_username=username, chat_id=str(chat_id))
        db.add(tg_user)
    db.commit()

    await message.answer(f"Привет, @{username}! Я запомнил твой chat_id.")


async def send_tg_code(
    telegram_username: str, code: str, db: Session = next(db.get_db())
):
    tg_user = (
        db.query(TelegramUser).filter_by(telegram_username=telegram_username).first()
    )
    if not tg_user:
        raise ValueError(f"Пользователь @{telegram_username} не зарегистрирован у бота")
    await bot.send_message(int(tg_user.chat_id), f"Ваш код для аутентификации: {code}")


def main():
    dp.start_polling(bot)


if __name__ == "__main__":
    main()
