from fastapi import FastAPI

from routes.events import router as events_router


app = FastAPI(
    title="API Threat Detection System",
    description="Backend for the intelligent API and network threat detection system",
    version="1.0.0",
)


app.include_router(events_router)


@app.get("/")
def root():
    return {
        "message": "API Threat Detection Backend is running"
    }