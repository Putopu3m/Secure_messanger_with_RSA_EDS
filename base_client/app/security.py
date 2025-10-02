import hashlib
import secrets

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password_bcrypt(password: str) -> str:
    return pwd_context.hash(password)


def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_bcrypt(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def hash_code_sha256(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def generate_tg_code() -> str:
    return str(secrets.randbelow(900000) + 100000)  # 6-значный код
