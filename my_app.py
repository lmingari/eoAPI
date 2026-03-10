import os
import secrets

from stac_fastapi.pgstac.app import app

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

# ---------------------------------------------------------
# Configuration (fail fast if missing)
# ---------------------------------------------------------

API_KEY = os.environ.get("STAC_API_KEY")
if not API_KEY:
    raise RuntimeError("STAC_API_KEY environment variable is required")

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

PUBLIC_WRITE_PATHS = {
    "/search",
}

bearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------

@app.middleware("http")
async def auth_middleware(request: Request, call_next):

    path = request.url.path
    method = request.method

    # ---- Protect write operations ----
    if method in WRITE_METHODS and path not in PUBLIC_WRITE_PATHS:

        credentials = await bearer(request)

        if credentials is None:
            return JSONResponse(
                {"detail": "Authentication required"},
                status_code=401
            )

        if not secrets.compare_digest(credentials.credentials, API_KEY):
            return JSONResponse(
                {"detail": "Invalid token"},
                status_code=403
            )

    response = await call_next(request)

    return response
