from fastapi import APIRouter

from schemas.api_security_event import ApiSecurityEvent
from services.event_processor import EventProcessor


router = APIRouter()

processor = EventProcessor()


@router.post("/events")
def receive_event(event: ApiSecurityEvent):
    return processor.process(event)