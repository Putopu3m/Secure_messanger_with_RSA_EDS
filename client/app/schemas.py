from pydantic import BaseModel


class ChallengeRequest(BaseModel):
    username: str


class LoginRequest(ChallengeRequest):
    password: str
    tg_code: str | None = None
