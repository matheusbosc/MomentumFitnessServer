#  SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from pydantic import BaseModel
from sqlalchemy.orm import Session
from models import User, RefreshToken
from db import get_db
from passlib.context import CryptContext
import uuid

import jwt

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

AUTH_SECRET_KEY = "593a862c9354f739d973edba2fa1924ef6eda83ed25b038f684253d7a213a186"
REFRESH_SECRET_KEY = "ed8384a37d0a1b10a919a8e292c25f769c7e08f030de183963c1c90deb522d05"
ALGORITHM = "HS256"
AUTH_EXPIRY = 300#3600
REFRESH_EXPIRY = 120#2592000

class RefreshRequest(BaseModel): 
    access_token: str 
    refresh_token: str

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
            raise HTTPException(status_code=401, detail="Invalid Credentials")

        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Token!")

# endregion

# region ENDPOINTS

@router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    
    # 1. Get user

    if "@" in email:
        user: User = db.query(User).filter(User.email == email).first() # --- SELECT * FROM users WHERE email = ? LIMIT 1;

    else:
        user: User = db.query(User).filter(User.username == email).first() # --- SELECT * FROM users WHERE username = ? LIMIT 1;

    if not user:
            raise HTTPException(status_code=401, detail="Invalid Credentials")
        
    if not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid Credentials!")
    
    # 2. Create IDs
    refresh_id_uuid = uuid.uuid4()
    refresh_id = str(refresh_id_uuid)
    access_token = create_access_token({"sub": user.username})
    refresh_token = create_refresh_token({"sub": refresh_id})

    # 3. Store the refresh token ID in DB
    new_token = RefreshToken(user_id=user.username, refresh_id=refresh_id)
    db.add(new_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/check_refresh_status")
@router.post("/refresh_token")
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):

    # Decode auth token
    try:
        payload = jwt.decode(body.access_token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Auth Token")

    # Decode refresh token
    try:
        payload2 = jwt.decode(body.refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_id = payload2.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Refresh Token")

    # Look up in DB
    stored = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.refresh_id == refresh_id
    ).first()

    if not stored:
        raise HTTPException(status_code=401, detail="Token Mismatch")

    # Issue new tokens
    new_access = create_access_token({"sub": user_id})
    new_refresh_id_uuid = uuid.uuid4()
    new_refresh_id = str(new_refresh_id_uuid)

    new_refresh_token = create_refresh_token({"sub": new_refresh_id})

    # Update DB
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