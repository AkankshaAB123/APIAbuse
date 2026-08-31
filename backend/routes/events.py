from fastapi import APIRouter

from schemas.api_security_event import ApiSecurityEvent


router = APIRouter(
    prefix="/events",
    tags=["Events"],
)


@router.post("")
def receive_event(event: ApiSecurityEvent):
    return {
        "message": "Event received successfully",
        "event": event.model_dump(mode="json"),
    }