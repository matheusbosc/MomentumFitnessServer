#  SPDX-License-Identifier: AGPL-3.0-or-later

from fastapi import FastAPI
from auth.routes import router as auth_router
from account.routes import router as account_router

app = FastAPI(docs_url="/docs", redoc_url="/redoc", root_path="/api")

app.include_router(auth_router, prefix="/api/v1/auth")
app.include_router(account_router, prefix="/api/v1/account")
