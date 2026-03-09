import os
import secrets

from stac_fastapi.pgstac.app import app

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------
# Configuration (fail fast if missing)
# ---------------------------------------------------------

API_KEY = os.environ.get("STAC_API_KEY")
if not API_KEY:
    raise RuntimeError("STAC_API_KEY environment variable is required")

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

bearer = HTTPBearer(auto_error=False)

# ---------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------

@app.middleware("http")
async def protect_transactions(request: Request, call_next):

    if request.method in WRITE_METHODS and request.url.path.startswith("/collections"):

        credentials = await bearer(request)

        if credentials is None:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)

        if not secrets.compare_digest(credentials.credentials, API_KEY):
            return JSONResponse({"detail": "Invalid token"}, status_code=403)

    return await call_next(request)

# ---------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}

# ---------------------------------------------------------
# Static assets
# ---------------------------------------------------------

app.mount("/data", StaticFiles(directory="/data"), name="data")

# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
