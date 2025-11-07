import sqlalchemy.orm
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

import base_client.app.api.router_api as router_api
import base_client.app.db
import base_client.app.services
from security import security

router = APIRouter()
manager = base_client.app.services.ConnectionManager()


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: int,
    db: sqlalchemy.orm.Session = Depends(base_client.app.db.get_db),
):
    if user_id == 0:
        await manager.connect_admin(websocket)
        try:
            while True:
                _ = await websocket.receive_text()
        except WebSocketDisconnect:
            await manager.disconnect_admin(websocket)
        return

    await manager.connect_user(websocket, user_id)

    try:
        while True:
            data = await websocket.receive_text()
            key = router_api.session_data.get("aes_key")
            if not key:
                continue

            try:
                plaintext = security.aes_decrypt(data, key)
            except Exception as e:
                print("Could not decrypt message:", e)
                continue

            await manager.broadcast_message_from_user_to_admins(user_id, plaintext)

    except WebSocketDisconnect:
        await manager.disconnect_user(user_id)
