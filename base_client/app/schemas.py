from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str
    telegram_username: str


class RegisterResponse(BaseModel):
    status: str
    message: str
