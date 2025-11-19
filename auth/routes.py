from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
import jwt

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

SECRET_KEY = "593a862c9354f739d973edba2fa1924ef6eda83ed25b038f684253d7a213a186"
ALGORITHM = "HS256"

# --- Create Tokens ---
def create_access_token(data: dict, expires_in: int = 60):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(seconds=expires_in)
    to_encode["exp"] = expire

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Login endpoint ---
@router.post("/api/v3/login")
def login(email: str, password: str):
    # validate credentials (temporary since thers no db yet)
    if email != "test@example.com" or password != "123":
        raise HTTPException(status_code=401, detail="Invalid Credentials!")

    user_id = "abc123"
    token = create_access_token({"sub": user_id})
    return {"access_token": token, "token_type": "bearer"}

# --- Dependency for protected routes ---
def get_current_user(token: str = Depends(oauth2_scheme)): #Depends() unencrypts the token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid Token!")


@router.get("/api/v3/profile")
def get_profile(user_id: str):
    user_id = get_current_user(user_id)
    return {"user_id": user_id, "message": "Protected Content"}