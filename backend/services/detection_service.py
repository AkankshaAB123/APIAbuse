from collections.abc import Sequence

from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.detector_result import DetectorResult
from backend.services.event_repository import EventRepository

from api_detection.backend_adapter import run_for_backend


class DetectionService:

    repository = EventRepository()

    def detect(
        self,
        event: ApiSecurityEvent,
        recent_events: Sequence[ApiSecurityEvent] | None = None,
    ) -> list[DetectorResult]:

        if recent_events is None:
            recent_events = self.repository.get_recent_events(event)

        results = run_for_backend(
            event,
            recent_events,
        )

        return [
            DetectorResult.model_validate(result)
            for result in results
        ]