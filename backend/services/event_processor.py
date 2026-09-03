from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.processing_result import ProcessingResult
from backend.services.detection_service import DetectionService
from backend.services.event_repository import EventRepository
from backend.services.ml_service import MLService
from backend.services.risk_engine import RiskEngine
from backend.services.mitigation_service import MitigationService


class EventProcessor:
    repository = EventRepository()
    detection_service = DetectionService()
    ml_service = MLService()
    risk_engine = RiskEngine()
    mitigation_service = MitigationService()

    def process(
        self,
        event: ApiSecurityEvent,
        ml_features: dict | None = None,
    ) -> ProcessingResult:

        recent_events = self.repository.get_recent_events(event)

        self.repository.save_event(event)

        detector_results = self.detection_service.detect(
            event,
            recent_events,
        )

        ml_result = None

        if ml_features:
            ml_result = self.ml_service.detect(ml_features)

        risk_assessment = self.risk_engine.assess(
            event_id=event.event_id,
            detector_results=detector_results,
            ml_result=ml_result,
        )

        mitigation_action = self.mitigation_service.decide_action(
            risk_assessment
        )

        processing_result = ProcessingResult(
            event_id=event.event_id,
            source_ip=event.network.source_ip,
            status="processed",
            message="Event processed successfully",
            detector_results=detector_results,
            ml_result=ml_result,
            risk_assessment=risk_assessment,
            mitigation_action=mitigation_action,
        )
        self.repository.update_processing_result(
            event.event_id,
            processing_result,
        )

        return processing_result