#  SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from models import User, RefreshToken
from db import get_db
from passlib.context import CryptContext
from dotenv import load_dotenv
from pathlib import Path

import uuid
import os
import re
import jwt

parent = Path(__file__).resolve().parent.parent  # 2 levels up
env_path = parent / ".env"
load_dotenv(dotenv_path=env_path)
env = os.environ

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
ALGORITHM = "HS256"
AUTH_EXPIRY = 300#3600
REFRESH_EXPIRY = 120#2592000
EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

class RefreshRequest(BaseModel): 
    access_token: str 
    refresh_token: str

class UserRequest(BaseModel):
    username: str
    email: str
    firstname: str
    lastname: str
    password: str

# region HELPER FUNCTIONS 


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# --- Create Tokens ---
def create_access_token(data: dict, expires_in: int = AUTH_EXPIRY):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(seconds=expires_in)
    to_encode["exp"] = expire

    return jwt.encode(to_encode, AUTH_SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict, expires_in: int = REFRESH_EXPIRY):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(seconds=expires_in)
    to_encode["exp"] = expire

    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)

# --- Dependency for protected routes ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        user: User = db.query(User).filter(User.username == user_id).first() # --- SELECT * FROM users WHERE email = ? LIMIT 1;
        if not user:
            raise HTTPException(status_code=401, detail="invalid Credentials")

        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid Token!")

# endregion

# region ENDPOINTS

@router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    
    # 1. Get user

    query_user: User

    if re.fullmatch(EMAIL_REGEX, email):
        query = (
            select(User)
            .where(User.email == email)
            .limit(1)
        ) # --- SELECT * FROM users WHERE email = ? LIMIT 1;

        for user in db.scalars(query):
            query_user = user
            break

        else:
            raise HTTPException(status_code=401, detail="invalid Credentials")

    else:
        query = (
            select(User)
            .where(User.username == email)
            .limit(1)
        ) # --- SELECT * FROM users WHERE username = ? LIMIT 1;

        for user in db.scalars(query):
            query_user = user
            break

        else:
            raise HTTPException(status_code=401, detail="invalid Credentials")
    
    if not verify_password(password, query_user.password):
        raise HTTPException(status_code=401, detail="invalid Credentials!")

    # 2. Create IDs
    refresh_id_uuid = uuid.uuid4()
    refresh_id = str(refresh_id_uuid)
    access_token = create_access_token({"sub": query_user.username})
    refresh_token = create_refresh_token({"sub": refresh_id})

    # 3. Store the refresh token ID in DB
    db.execute(
        delete(RefreshToken).where(RefreshToken.user_id == query_user.username)
    )
    new_token = RefreshToken(user_id=query_user.username, refresh_id=refresh_id)
    db.add(new_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/register")
def register(body: UserRequest, db: Session = Depends(get_db)):
    # 1. Verify if all data is filled correctly
    if not re.fullmatch(EMAIL_REGEX, body.email):
        raise HTTPException(status_code=400, detail="invalid email")
    
    if len(body.username) > 12 or len(body.username) < 3:
        raise HTTPException(status_code=400, detail="username too long/short")
    
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="password too short")

    # 2. Verify if user exists or doesnt exist

    query = (
        select(User)
        .where(User.email == body.email)
    )
    
    for user in db.scalars(query):
        raise HTTPException(status_code=409, detail="email in use")
    
    query = (
        select(User)
        .where(User.username == body.username)    
    )

    for user in db.scalars(query):
        raise HTTPException(status_code=409, detail="username in use")

    # 3. Process and Commit Data

    hashed_password = hash_password(body.password)
    db_user = User(
        email=body.email,
        username=body.username,
        password=hashed_password,
        firstname=body.firstname,
        lastname=body.lastname
    )

    db.add(db_user)
    db.commit()

    # 4. Login

    login_response = login(email=body.email, password=body.password, db=db)

    return login_response

@router.post("/check_refresh_status")
@router.post("/refresh_token")
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):

    # Decode auth token
    try:
        payload = jwt.decode(body.access_token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")

    # Decode refresh token
    try:
        payload2 = jwt.decode(body.refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_id = payload2.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")

    # Look up in DB
    stored: RefreshToken = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.refresh_id == refresh_id
    ).first()

    if not stored:
        raise HTTPException(status_code=401, detail="token mismatch")

    # Issue new tokens
    new_access = create_access_token({"sub": user_id})
    new_refresh_id_uuid = uuid.uuid4()
    new_refresh_id = str(new_refresh_id_uuid)

    new_refresh_token = create_refresh_token({"sub": new_refresh_id})

    # Update DB
    db.execute(
        delete(RefreshToken).where(RefreshToken.id == stored.id)
    )
    stored.refresh_id = new_refresh_id
    db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh_token
    }

@router.get("/profile")
def get_profile(user_id: str, db: Session = Depends(get_db)):
    user: User = get_current_user(user_id, db=db)
    return {"user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "first_name": user.firstname,
            "last_name": user.lastname,
            "message": "Protected Content"}

@router.get("/dev/gen_password")
def gen_pass(password: str):
    return { "password": hash_password(password) }

# endregion