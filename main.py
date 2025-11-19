#  SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import FastAPI
from auth.routes import router as auth_router

app = FastAPI()

app.include_router(auth_router, prefix="/api/v1/auth")
