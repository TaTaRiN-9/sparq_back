from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from chat import app
from chat.crud import (
    create_user_controller,
    get_user_groups_by_id,
)
from chat.database import get_db
from chat.schema import CreateUser, User
from chat.utils.exception import (
    AlreadyExistsException,
)
from chat.utils.jwt import (
    get_current_active_user,
)


@app.get("/user/me", tags=["User"], response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    return current_user


@app.get("/user/unread_messages", tags=["User"])
async def unread_messages(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user.unread_messages


@app.post("/user/create", response_model=User, tags=["User"])
async def create_user(user: CreateUser, db: Session = Depends(get_db)):
    created_user = await create_user_controller(db=db, user=user)
    if created_user:
        return created_user
    raise AlreadyExistsException


@app.get("/user/groups", tags=["User"])
async def get_user_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    user_groups = await get_user_groups_by_id(user_id=current_user.id, db=db)
    groups_with_ids = [
        {
            "id": group.id,
            "name": group.name,
            "address": group.address,
        }
        for group in user_groups
    ]
    return {
        "user_id": current_user.id,
        "groups": groups_with_ids,
    }
