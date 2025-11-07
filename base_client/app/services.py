import json
from typing import Dict, Set

from fastapi import WebSocket

import base_client.app.api.router_api as router_api
from base_client.app.db import SessionLocal
from base_client.app.models import Message
from security import security


class ConnectionManager:
    def __init__(self):
        self.admin_connections: Set[WebSocket] = set()
        self.user_connections: Dict[int, WebSocket] = {}

    def save_message(self, user_id: int, sender: str, text: str):
        db = SessionLocal()
        msg = Message(user_id=user_id, sender=sender, content=text)
        db.add(msg)
        db.commit()
        db.close()

    def load_messages(self, user_id: int):
        db = SessionLocal()
        msgs = (
            db.query(Message)
            .filter(Message.user_id == user_id)
            .order_by(Message.created_at.asc())
            .all()
        )
        db.close()
        return msgs

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.add(websocket)
        await self.send_users_list_to_admins()

        db = SessionLocal()
        all_msgs = db.query(Message).order_by(Message.created_at.asc()).all()
        db.close()
        for msg in all_msgs:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "message",
                        "from": msg.sender,
                        "text": msg.content,
                        "user": str(msg.user_id),
                    }
                )
            )

    async def disconnect_admin(self, websocket: WebSocket):
        self.admin_connections.discard(websocket)
        try:
            await websocket.close()
        except Exception:
            pass

    async def connect_user(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.user_connections[user_id] = websocket

        await self.broadcast_to_admins(
            {"type": "user_joined", "username": str(user_id)}
        )
        await self.send_users_list_to_admins()

        key = router_api.session_data.get("aes_key")
        if key:
            messages = self.load_messages(user_id)
            for msg in messages:
                data = {
                    "sender": msg.sender,
                    "text": msg.content,
                    "timestamp": msg.created_at.isoformat()
                }
                enc = security.aes_encrypt(json.dumps(data), key)
                await websocket.send_text(enc)

    async def disconnect_user(self, user_id: int):
        ws = self.user_connections.pop(user_id, None)
        if ws:
            try:
                await ws.close()
            except Exception:
                pass

        await self.broadcast_to_admins({"type": "user_left", "username": str(user_id)})
        await self.send_users_list_to_admins()

    async def broadcast_to_admins(self, obj: dict):
        remove = []
        text = json.dumps(obj)
        for a in list(self.admin_connections):
            try:
                await a.send_text(text)
            except Exception:
                remove.append(a)
        for a in remove:
            self.admin_connections.discard(a)

    async def send_users_list_to_admins(self):
        users = [str(uid) for uid in self.user_connections.keys()]
        await self.broadcast_to_admins({"type": "users_list", "users": users})

    async def broadcast_message_from_user_to_admins(self, user_id: int, plaintext: str):
        self.save_message(user_id, str(user_id), plaintext)
        await self.broadcast_to_admins(
            {"type": "message", "from": str(user_id), "text": plaintext}
        )

    async def broadcast_message_from_admin_to_user(self, user_id: int, plaintext: str, key):
        self.save_message(user_id, "admin", plaintext)

        if key:
            data = {"sender": "admin", "text": plaintext}
            enc = security.aes_encrypt(json.dumps(data), key)
            ws = self.user_connections.get(user_id)
            if ws:
                await ws.send_text(enc)
