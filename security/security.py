import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

CODE_TTL = 120  # 2 minutes

BLOCK_SIZE = 16  # 128 бит


def hash_bcrypt(password: str) -> str:
    return pwd_context.hash(password)


def verify_bcrypt(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def hash_sha256(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def generate_tg_code() -> str:
    return secrets.token_hex(3)


def is_code_expired(created_at: datetime) -> bool:
    return datetime.now(timezone.utc) > created_at + timedelta(seconds=CODE_TTL)


def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> str:
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify_signature(
    public_key: rsa.RSAPublicKey, message: bytes, signature_b64: str
) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()


def load_public_key(pubkey_b64: str) -> rsa.RSAPublicKey:
    data = base64.b64decode(pubkey_b64.encode())
    return serialization.load_pem_public_key(data)


def generate_dh_params() -> tuple[int, int]:
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
        16,
    )
    g = 2
    return p, g


def generate_dh_keypair(p: int, g: int) -> tuple[int, int]:
    private = int.from_bytes(os.urandom(32), "big")
    public = pow(g, private, p)
    return private, public


def compute_shared_secret(peer_public: int, private: int, p: int) -> bytes:
    secret = pow(peer_public, private, p)
    key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"AES key").derive(
        secret.to_bytes(256, "big")
    )
    return key


def aes_encrypt(message: str, key: bytes) -> str:
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(key[:16], AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encrypted_message: str, key: bytes) -> str:
    raw = base64.b64decode(encrypted_message)
    iv = raw[:BLOCK_SIZE]
    ciphertext = raw[BLOCK_SIZE:]
    cipher = AES.new(key[:16], AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return plaintext.decode()