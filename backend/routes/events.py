from fastapi import APIRouter, HTTPException
from backend.schemas.event_request import EventProcessingRequest
from backend.services.event_processor import EventProcessor


router = APIRouter()

processor = EventProcessor()


@router.post("/events")
def receive_event(request: EventProcessingRequest):
    try:
        return processor.process(
            event=request.event,
            ml_features=request.ml_features,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Event processing failed",
        ) from exc