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


@router.post("/events/{event_id}/enforcement")
def update_event_enforcement(event_id: str, data: dict):
    """Allow active defense gateways to record real enforcement decisions into MongoDB."""
    try:
        from backend.database import events_collection
        action = data.get("action", "BLOCK")
        status_code = int(data.get("status_code", 403))
        events_collection.update_one(
            {"event_id": event_id},
            {
                "$set": {
                    "processing.mitigation_action": action,
                    "processing.mitigation": {
                        "enforced": True,
                        "result": action,
                        "status_code": status_code,
                    },
                    "response.status_code": status_code,
                    "after_mitigation.status_code": status_code,
                }
            },
        )
        return {"status": "enforced", "event_id": event_id, "action": action}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
