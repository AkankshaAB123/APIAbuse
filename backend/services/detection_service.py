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
            try:
                recent_events = self.repository.get_recent_events(event)
            except Exception as exc:
                print(
                    f"[WARN] DetectionService failed to get recent events: {exc}. "
                    "Using empty history."
                )
                recent_events = []

        results = run_for_backend(
            event,
            recent_events,
        )

        validated_results: list[DetectorResult] = []
        for result in results:
            try:
                validated_results.append(DetectorResult.model_validate(result))
            except Exception as exc:
                print(f"[WARN] Failed to validate detector result: {exc}")

        return validated_results