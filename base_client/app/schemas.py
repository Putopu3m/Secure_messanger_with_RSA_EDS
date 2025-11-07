from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str
    telegram_username: str


class RegisterResponse(BaseModel):
    status: str
    message: str


class AuthRequest(BaseModel):
    username: str
    response_hash: str


class ChallengeRequest(BaseModel):
    username: str


class DHInitiateRequest(BaseModel):
    p: str
    g: str
    A: str
    signature: str
    client_rsa_pub: str


class SendMessage(BaseModel):
    user_id: str
    text: str
