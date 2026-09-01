from schemas.api_security_event import ApiSecurityEvent
from schemas.processing_result import ProcessingResult


class EventProcessor:
    def process(self, event: ApiSecurityEvent) -> ProcessingResult:
        return ProcessingResult(
            event_id=event.event_id,
            status="processed",
            message="Event processed successfully",
        )