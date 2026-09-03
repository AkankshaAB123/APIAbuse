from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes.events import router as events_router
from backend.routes.threats import router as threats_router


app = FastAPI(
    title="API Threat Detection System",
    description="Backend for the intelligent API and network threat detection system",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://apiabuse.onrender.com",
    ],

    allow_credentials=False,

    allow_methods=["*"],

    allow_headers=["*"],
)


# =========================================================
# ROUTES
# =========================================================

app.include_router(
    events_router
)

app.include_router(
    threats_router
)


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "message":
            "API Threat Detection Backend is running"
    }