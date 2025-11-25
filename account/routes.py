#  SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from models import User
from db import get_db
from passlib.context import CryptContext
from dotenv import load_dotenv
from pathlib import Path

import os
import jwt

parent = Path(__file__).resolve().parent.parent  # 2 levels up
env_path = parent / ".env"
load_dotenv(dotenv_path=env_path)
env = os.environ

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY")
ALGORITHM = "HS256"

class AuthToken(BaseModel):
    access_token: str

class UserRequest(BaseModel):
    username: str
    email: str
    firstname: str
    lastname: str
    password: str

# region HELPER FUNCTIONS 

# --- Dependency for protected routes ---
def get_user(token: str = Depends(oauth2_scheme), user_id: str = "", db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="invalid Token!")
    
    user: User

    if user_id.startswith("uname\\"):
        user_id = user_id[6::]
        query = select(User).where(User.username == user_id).limit(1)

        for q_user in db.scalars(query):
            user = q_user
            break
        else:
            raise HTTPException(status_code=400, detail="invalid credentials")
    if user_id.startswith("id\\"):
        user_id = user_id[3::]
        query = select(User).where(User.user_id == user_id).limit(1)

        for q_user in db.scalars(query):
            user = q_user
            break
        else:
            raise HTTPException(status_code=400, detail="invalid credentials")
    else:
        raise HTTPException(status_code=500, detail="endpoint code not correct")

    return user

def delete_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db())):
    try:
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="invalid Token!")
    
    user: User = payload.get("sub")
    user_id = user.user_id

    query = select(User).where(User.user_id == user_id).limit(1)

    for q_user in db.scalars(query):
        break
    else:
        raise HTTPException(status_code=404, detail="user not found")

    delete(User).where(User.user_id == user_id)
    db.commit()

    return

# endregion

# region ENDPOINTS

@router.get("/user/{username}")
def get_profile(username, body = AuthToken, db: Session = Depends(get_db)):
    user: User = get_user(token=body.access_token, user_id="uname\\" + username, db=db)
    return {"user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "first_name": user.firstname,
            "last_name": user.lastname,
            "message": "Protected Content"}

@router.get("/user/id/{user_id}")
def get_profile(user_id, body = AuthToken, db: Session = Depends(get_db)):
    user: User = get_current_user(token=body.access_token, user_id="uname\\" + user_id, db=db)
    return {"user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "first_name": user.firstname,
            "last_name": user.lastname,
            "message": "Protected Content"}

@router.delete("/user/{username}")
def get_profile(username, body = AuthToken, db: Session = Depends(get_db)):
    delete_user(token = body.access_token, db = db)

# endregion