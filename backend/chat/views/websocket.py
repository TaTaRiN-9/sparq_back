import asyncio
import json

from fastapi import Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from chat import app, logger, models
from chat.crud import (
    create_message_controller,
    create_unread_message_controller,
    get_group_by_id,
    group_membership_check,
)
from chat.database import get_db
from chat.models import Message, User
from chat.utils.jwt import get_current_user

websocket_connections = {}


@app.websocket("/send-message")
async def send_messages_endpoint(
    websocket: WebSocket,
    db: Session = Depends(get_db),
) -> None:
    token = websocket.query_params.get("token")
    group_id = websocket.query_params.get("group_id")
    if token and group_id:
        user = await get_current_user(user_db=db, token=token)
        group_id = int(group_id)
    else:
        return await websocket.close(reason="You're not allowed", code=4403)
    is_group_member = await group_membership_check(
        group_id=group_id,
        db=db,
        user=user,
    )
    if not is_group_member:
        logger.error(
            "User %s Connect to Send Messages But not allowed with group id : %s",
            user.username,
            group_id,
        )
        return await websocket.close(reason="You're not allowed", code=4403)
    if user:
        logger.info(
            "User %s Connect to Send Messages endpoint group id : %s",
            user.username,
            group_id,
        )
        user.websocket = websocket
        await websocket.accept()
        while True:
            try:
                data = await websocket.receive_text()
            except WebSocketDisconnect as error_message:
                logger.info(
                    "User %s Disconnect from Send Messages endpoint group id : %s, %s",
                    user.username,
                    group_id,
                    error_message,
                )
                break
            if data is None:
                break
            message = await create_message_controller(
                db=db, user=user, group_id=group_id, text=data
            )
            
            asyncio.create_task(broadcast_message(group_id, message, db))


async def broadcast_message(group_id: int, message: Message, db) -> None:
    group = await get_group_by_id(db=db, group_id=group_id)
    if group:
        for member in group.members:
            await create_unread_message_controller(
                db=db,
                message=message,
                user=member.user,
                group_id=group_id,
            )
            if member.user.websocket:
                asyncio.create_task(member.user.websocket.send_text(message.text))


@app.websocket("/get-unread-messages")
async def send_unread_messages_endpoint(
    websocket: WebSocket,
    db: Session = Depends(get_db),
) -> None:
    token = websocket.query_params.get("token")
    group_id = websocket.query_params.get("group_id")
    if token and group_id:
        user = await get_current_user(user_db=db, token=token)
        group_id = int(group_id)
    else:
        return await websocket.close(reason="You're not allowed", code=4403)
    is_group_member = await group_membership_check(
        group_id=group_id,
        db=db,
        user=user,
    )
    if not is_group_member:
        return await websocket.close(reason="You're not allowed", code=4403)
    if user:
        if user.id in websocket_connections:
            logger.error(
                "User %s Has More Than 1 Websocket With Group id : %s",
                user.username,
                group_id,
            )
            return await websocket.close(reason="You're not allowed", code=4403)
        websocket_connections[user.id] = websocket
        await websocket.accept()
        try:
            await send_unread_messages(websocket, user, group_id, db)
        except (WebSocketDisconnect, RuntimeError):
            pass
    else:
        return await websocket.close()


async def send_unread_messages(
    websocket: WebSocket,
    user: User,
    group_id: int,
    db: Session = Depends(get_db),
):
    while True:
        db.refresh(user)
        all_unread_messages: models.UnreadMessage = user.unread_messages
        unread_messages_group: list[models.UnreadMessage] = []
        if all_unread_messages:
            unread_messages_group = [
                un_mes
                for un_mes in all_unread_messages
                if str(un_mes.group_id) == str(group_id)
            ]
            await send_messages_concurrently(websocket, unread_messages_group)
            for message in all_unread_messages:
                db.delete(message)
            db.commit()
        else:
            try:
                await asyncio.wait_for(websocket.receive(), timeout=0.7)
                continue
            except asyncio.TimeoutError:
                continue
            except (WebSocketDisconnect, RuntimeError):
                if websocket_connections[user.id]:
                    websocket_connections.pop(user.id)
                break


async def broadcast_changes(
    group_id: int,
    change_type: models.ChangeType,
    db: Session,
    message_id: int | None = None,
    new_text: str | None = None,
) -> None:
    group = await get_group_by_id(db=db, group_id=group_id)
    if group:
        changed_value = {
            "type": change_type,
            "id": message_id,
            "new_text": new_text,
        }
        online_users = set(websocket_connections.keys())
        await asyncio.gather(
            *[
                send_change_to_user(
                    member.user.id, changed_value, online_users=online_users
                )
                for member in group.members
            ]
        )


async def send_change_to_user(
    user_id: int, change_data: dict, online_users: set
) -> None:
    if user_id in online_users:
        connection = websocket_connections[
            user_id
        ]

        await connection.send_text(json.dumps(change_data))


async def send_messages_concurrently(
    websocket: WebSocket, messages: list[models.UnreadMessage]
):
    tasks = [
        websocket.send_text(
            json.dumps(
                {
                    "text": message.message.text,
                    "sender_name": message.message.sender_name,
                    "id": message.message.id,
                    "type": "Text",
                    "datetime": str(message.message.created_at),
                }
            )
        )
        for message in messages
    ]
    await asyncio.gather(*tasks)
