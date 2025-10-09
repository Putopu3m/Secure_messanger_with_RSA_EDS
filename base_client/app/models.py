from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import relationship

from .db import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_bcrypt = Column(String, nullable=False)
    password_sha256 = Column(String, nullable=False)
    telegram_username = Column(String, nullable=True)
    tg_code = relationship("TelegramCode", back_populates="user", uselist=False)
    chat_id = Column(BigInteger, nullable=True)
    challenges = relationship("Challenge", back_populates="user", uselist=False)


class TelegramCode(Base):
    __tablename__ = "tg_codes"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="tg_code")


class Challenge(Base):
    __tablename__ = "challenges"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="challenges")
