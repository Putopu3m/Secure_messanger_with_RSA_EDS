import json
from typing import Dict, Set

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        # admin sockets (user_id == 0 connects here)
        self.admin_connections: Set[WebSocket] = set()
        # user sockets: user_id (int) -> WebSocket
        self.user_connections: Dict[int, WebSocket] = {}

    # --------------- connects / disconnects ---------------
    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.add(websocket)
        # send current users list
        await self.send_users_list_to_admins()

    async def disconnect_admin(self, websocket: WebSocket):
        self.admin_connections.discard(websocket)
        try:
            await websocket.close()
        except Exception:
            pass

    async def connect_user(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.user_connections[user_id] = websocket
        # notify admins
        await self.broadcast_to_admins(
            {"type": "user_joined", "username": str(user_id)}
        )
        await self.send_users_list_to_admins()

    async def disconnect_user(self, user_id: int):
        ws = self.user_connections.pop(user_id, None)
        if ws:
            try:
                await ws.close()
            except Exception:
                pass
        # notify admins
        await self.broadcast_to_admins({"type": "user_left", "username": str(user_id)})
        await self.send_users_list_to_admins()

    # --------------- broadcasting helpers ---------------
    async def broadcast_to_admins(self, obj: dict):
        # send JSON to all admin connections
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
        await self.broadcast_to_admins(
            {"type": "message", "from": str(user_id), "text": plaintext}
        )

    # expose send-to-user so other code (e.g. /send_to_user endpoint) can call:
    async def send_encrypted_to_user(self, user_id: int, encrypted_b64: str):
        ws = self.user_connections.get(user_id)
        if not ws:
            raise RuntimeError("User not connected")
        # send the encrypted base64 string verbatim to the user websocket (text frame)
        await ws.send_text(encrypted_b64)
