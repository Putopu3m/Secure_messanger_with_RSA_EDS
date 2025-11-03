import base64

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, dict[int, WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room_id: int, user_id: int):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = {}
        self.active_connections[room_id][user_id] = websocket

    async def disconnect(self, websocket: WebSocket, room_id: int, user_id: int):
        await websocket.close()
        if room_id in self.active_connections:
            self.active_connections[room_id].pop(user_id, None)
            if not self.active_connections[room_id]:
                self.active_connections.pop(room_id)

    async def broadcast(self, message: str, room_id: int, sender_id: int):
        if room_id in self.active_connections:
            for user_id, connection in self.active_connections[room_id].items():
                message_with_class = {"text": message, "is_self": user_id == sender_id}

                await connection.send_json(message_with_class)


def get_aes_key_bytes(session_data: dict[str, str]):
    b64 = session_data.get("aes_key")
    if not b64:
        return None
    try:
        key = base64.b64decode(b64)
        if len(key) < 16:
            return None
        return key[:16]
    except Exception:
        return None
