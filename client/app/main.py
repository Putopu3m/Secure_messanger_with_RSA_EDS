import base64

import httpx
from fastapi import FastAPI, HTTPException

from security import security

from . import schemas

app = FastAPI()

BASE_CLIENT_URL = "http://localhost:8000"

session_data = {}


@app.post("/create_challenge")
async def create_challenge(challenge_request: schemas.ChallengeRequest):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/challenge",
            json={
                "username": challenge_request.username,
            },
        )

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Login failed")

    session_data[challenge_request.username] = response.json().get("challenge_hash")

    return {"message": "Challenge создан. Проверьте Telegram для кода."}


@app.post("/authenticate")
async def authenticate(login_request: schemas.LoginRequest):
    if login_request.username not in session_data:
        raise HTTPException(status_code=400, detail="No active challenge")

    challenge_hash = session_data.pop(login_request.username)

    password_sha256 = security.hash_sha256(login_request.password)
    code_sha256 = security.hash_sha256(login_request.tg_code)

    response = security.hash_sha256((password_sha256 + challenge_hash + code_sha256))

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_CLIENT_URL}/authenticate",
            json={"username": login_request.username, "response_hash": response},
        )

    if response.status_code == 200:
        p, g = security.generate_dh_params()
        a, A = security.generate_dh_keypair(p, g)
        rsa_priv, rsa_pub = security.generate_rsa_keypair()

        message = f"{p}{g}{A}".encode()
        signature = security.sign_message(rsa_priv, message)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BASE_CLIENT_URL}/dh/respond",
                json={
                    "p": str(p),
                    "g": str(g),
                    "A": str(A),
                    "signature": signature,
                    "client_rsa_pub": security.serialize_public_key(rsa_pub),
                },
            )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        data = response.json()
        B = int(data["B"])
        server_signature = data["signature"]
        server_pub = security.load_public_key(data["server_rsa_pub"])

        # Проверяем подпись сервера
        if not security.verify_signature(server_pub, f"{B}".encode(), server_signature):
            raise HTTPException(
                status_code=400, detail="Invalid RSA signature from server"
            )

        # Общий ключ
        shared_key = security.compute_shared_secret(B, a, p)
        session_data["aes_key"] = base64.b64encode(shared_key).decode()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return {"message": "DH successful", "shared_key": session_data["aes_key"]}


# @app.post("/dh/initiate")
# async def dh_initiate():
#     with xmlrpc.client.ServerProxy("http://localhost:8002/") as proxy:
#         p, g = proxy.generate_dh_params()
#         a, A = proxy.generate_dh_keypair(p, g)
#         rsa_priv, rsa_pub = proxy.generate_rsa_keypair()

#         message = f"{p}{g}{A}".encode()
#         signature = proxy.sign_message(rsa_priv, message)

#         async with httpx.AsyncClient() as client:
#             response = await client.post(
#                 f"{BASE_CLIENT_URL}/dh/respond",
#                 json={
#                     "p": str(p),
#                     "g": str(g),
#                     "A": str(A),
#                     "signature": signature,
#                     "client_rsa_pub": proxy.serialize_public_key(rsa_pub),
#                 },
#             )

#         if response.status_code != 200:
#             raise HTTPException(status_code=response.status_code, detail=response.text)

#         data = response.json()
#         B = int(data["B"])
#         server_signature = data["signature"]
#         server_pub = proxy.load_public_key(data["server_rsa_pub"])

#         # Проверяем подпись сервера
#         if not proxy.verify_signature(server_pub, f"{B}".encode(), server_signature):
#             raise HTTPException(status_code=400, detail="Invalid RSA signature from server")

#         # Общий ключ
#         shared_key = proxy.compute_shared_secret(B, a, p)
#         session_data["aes_key"] = base64.b64encode(shared_key).decode()
#     return {"message": "DH successful", "shared_key": session_data["aes_key"]}
