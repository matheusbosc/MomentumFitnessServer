from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
import jwt

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

AUTH_SECRET_KEY = "593a862c9354f739d973edba2fa1924ef6eda83ed25b038f684253d7a213a186"
REFRESH_SECRET_KEY = "ed8384a37d0a1b10a919a8e292c25f769c7e08f030de183963c1c90deb522d05"
ALGORITHM = "HS256"
AUTH_EXPIRY = 30#3600
REFRESH_EXPIRY = 120#2592000

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

# --- Login endpoint ---
@router.post("/api/v1/auth/login")
def login(email: str, password: str):
    # validate credentials (temporary since thers no db yet)
    if email != "test@example.com" or password != "123":
        raise HTTPException(status_code=401, detail="Invalid Credentials!")

    user_id = "abc123"
    refresh_id = "xyz987"
    token = create_access_token({"sub": user_id})
    refresh_token = create_refresh_token({"sub": refresh_id})
    return {"access_token": token, "refresh_token": refresh_token, "token_type": "bearer"}

# --- Dependency for protected routes ---
def get_current_user(token: str = Depends(oauth2_scheme)): #Depends() unencrypts the token
    try:
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Token!")
    
@router.post("/api/v1/auth/refresh_token")
def refresh_token(auth_token: str, refresh_token: str): #Depends() unencrypts the token
    auth_token = Depends(oauth2_scheme)
    refresh_token = Depends(oauth2_scheme)

    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        refresh_token_decoded = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Refresh Token!")
    
    try:
        payload2 = jwt.decode(auth_token, AUTH_SECRET_KEY, algorithms=[ALGORITHM])
        auth_token_decoded = payload2.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Auth Token!")
    
    if auth_token_decoded != "user123" or refresh_token_decoded != "xyz987": # TODO: Change this to check for match in the database between 2 tokens
        raise HTTPException(status_code=401, detail="Invalid Credentials")

    new_auth = create_access_token({"sub": auth_token_decoded})
    new_refresh = create_refresh_token({"sub": refresh_token_decoded})

    return {"access_token": new_auth, "refresh_token": new_refresh}


@router.get("/api/v1/profile")
def get_profile(user_id: str):
    user_id = get_current_user(user_id)
    return {"user_id": user_id, "message": "Protected Content"}