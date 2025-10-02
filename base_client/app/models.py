from sqlalchemy import Column, Integer, String

from .db import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_bcrypt = Column(String, nullable=False)
    password_sha256 = Column(String, nullable=False)
    telegram_username = Column(String, nullable=True)
    tg_code_hash = Column(String, nullable=True)


class TelegramUser(Base):
    __tablename__ = "telegram_users"
    id = Column(Integer, primary_key=True, index=True)
    telegram_username = Column(String, unique=True, index=True, nullable=False)
    chat_id = Column(String, unique=True, nullable=False)
