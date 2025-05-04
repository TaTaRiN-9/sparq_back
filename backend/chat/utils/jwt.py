from datetime import datetime, timedelta
from typing import Annotated

import bcrypt
from chat import models
from chat.database import get_db, engine, Base
from chat.schema import TokenData, User
from chat.setting import setting
from chat.utils.exception import CredentialsException
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

Base.metadata.create_all(bind=engine)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    encoded_hashed_password = hashed_password.encode("utf-8")
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        encoded_hashed_password,
    )


def get_password_hash(password: str) -> str:
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed_bytes.decode("utf-8")


def get_user(user_db: Session, username: str) -> models.User:
    user = user_db.query(models.User).filter(models.User.username == username).first()
    return user


def authenticate_user(
    user_db: Session, username: str, password: str
) -> models.User | None:
    user = get_user(user_db, username)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    to_encode["id"] = int(to_encode.get("id"))
    encoded_jwt = jwt.encode(
        to_encode,
        setting.SECRET_KEY,
        algorithm=setting.ALGORITHM,
    )
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    user_db: Session = Depends(
        get_db,
    ),
) -> User:
    token_data = decode_jwt(token)
    user = get_user(user_db, username=token_data.username)
    
    if user is None:
        raise CredentialsException
    
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if current_user.disabled:
        raise HTTPException(
            status_code=400, detail="Inactive user"
        )
    
    return current_user


def get_admin_payload(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, setting.SECRET_KEY, setting.ALGORITHM)
        username: str = payload.get("username")
        id: int = int(payload.get("id"))
        return {"username": username, "id": id}
    except JWTError:
        return


def decode_jwt(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> TokenData | CredentialsException:
    try:
        payload = jwt.decode(
            token,
            setting.SECRET_KEY,
            algorithms=[setting.ALGORITHM],
        )
        username: str = payload.get("username")
        user_id: int = int(payload.get("id"))
        if username is None or user_id is None:
            raise CredentialsException
        token_data = TokenData(username=username, id=user_id)
    except JWTError:
        raise CredentialsException
    return token_data
