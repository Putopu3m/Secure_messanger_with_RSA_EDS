from fastapi import APIRouter, WebSocket, WebSocketDisconnect

import base_client.app.api.router_api as router_api
import base_client.app.services
from security import security

router = APIRouter()
manager = base_client.app.services.ConnectionManager()


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """
    If user_id == 0 -> admin socket (admin GUI connects here).
    Else -> user socket (client GUI connects here).
    """
    if user_id == 0:
        # admin
        await manager.connect_admin(websocket)
        try:
            while True:
                # admin socket can send control messages (not used now)
                _ = await websocket.receive_text()
                # ignore or extend for admin->server commands
        except WebSocketDisconnect:
            await manager.disconnect_admin(websocket)
        return

    # user socket
    await manager.connect_user(websocket, user_id)

    try:
        while True:
            # receive an encrypted base64 string from user
            data = await websocket.receive_text()

            # get AES key (from router_api.session_data). can be base64 or bytes.
            key = router_api.session_data.get("aes_key")
            if not key:
                # if no key — cannot decrypt; ignore
                continue

            try:
                # security.aes_decrypt expects (enc_b64, key) and will handle types
                plaintext = security.aes_decrypt(data, key)
            except Exception as e:
                print("Could not decrypt message:", e)
                # optionally notify admin of malformed message
                continue

            # broadcast plaintext to admins as JSON event
            await manager.broadcast_message_from_user_to_admins(user_id, plaintext)

    except WebSocketDisconnect:
        # user disconnected
        await manager.disconnect_user(user_id)
