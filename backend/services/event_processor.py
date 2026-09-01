from schemas.api_security_event import ApiSecurityEvent
from schemas.processing_result import ProcessingResult
from services.event_repository import EventRepository


class EventProcessor:
    repository = EventRepository()

    def process(self, event: ApiSecurityEvent) -> ProcessingResult:
        self.repository.save_event(event)

        return ProcessingResult(
            event_id=event.event_id,
            status="processed",
            message="Event processed successfully",
        )