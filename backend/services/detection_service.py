from schemas.api_security_event import ApiSecurityEvent
from schemas.detector_result import DetectorResult


class DetectionService:

    def detect(self, event: ApiSecurityEvent) -> list[DetectorResult]:
        """
        Run the available API security detectors for an event.

        Member 2's detectors will be connected here when they
        are available.
        """

        return []