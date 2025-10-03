import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

CODE_TTL = 120  # 2 minutes


def hash_password_bcrypt(password: str) -> str:
    return pwd_context.hash(password)


def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_bcrypt(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def hash_code_sha256(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def generate_tg_code() -> str:
    return secrets.token_hex(3)


def is_code_expired(created_at: datetime) -> bool:
    return datetime.now(timezone.utc) > created_at + timedelta(seconds=CODE_TTL)
