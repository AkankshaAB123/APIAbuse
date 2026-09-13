from typing import Union

from fastapi import APIRouter, HTTPException
from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.event_request import EventProcessingRequest
from backend.services.event_processor import EventProcessor


router = APIRouter()

processor = EventProcessor()


@router.post("/events")
def receive_event(request: Union[EventProcessingRequest, ApiSecurityEvent]):
    try:
        if isinstance(request, EventProcessingRequest):
            event = request.event
            ml_features = request.ml_features
        else:
            event = request
            ml_features = None

        return processor.process(
            event=event,
            ml_features=ml_features,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Event processing failed",
        ) from exc
