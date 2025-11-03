from fastapi import APIRouter, WebSocket, WebSocketDisconnect

import base_client.app.services

router = APIRouter()
manager = base_client.app.services.ConnectionManager()


@router.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: int, user_id: int):
    await manager.connect(websocket, room_id, user_id)
    await manager.broadcast(
        f"User {user_id} has joined the room {room_id}", room_id, user_id
    )
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(data, room_id, user_id)
    except WebSocketDisconnect:
        await manager.disconnect(websocket, room_id, user_id)
        await manager.broadcast(
            f"User {user_id} has left the room {room_id}", room_id, user_id
        )
