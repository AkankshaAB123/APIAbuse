from datetime import timedelta

from backend.schemas.api_security_event import ApiSecurityEvent
from backend.database import events_collection


class EventRepository:

    def save_event(self, event: ApiSecurityEvent):
        event_data = event.model_dump()

        events_collection.insert_one(event_data)

        return event_data

    def update_processing_result(self, event_id: str, processing_result):
        processing_data = {
            "detector_results": [
                result.model_dump()
                for result in processing_result.detector_results
            ],
            "ml_result": (
                processing_result.ml_result.model_dump()
                if processing_result.ml_result is not None
                else None
            ),
            "risk_assessment": (
                processing_result.risk_assessment.model_dump()
                if processing_result.risk_assessment is not None
                else None
            ),
            "mitigation_action": processing_result.mitigation_action,

            # RAG + Gemini AI analysis
            "ai_analysis": processing_result.ai_analysis,
        }

        events_collection.update_one(
            {"event_id": event_id},
            {"$set": {"processing": processing_data}},
        )

    def get_recent_events(
        self,
        event: ApiSecurityEvent,
        window_seconds: int = 300,
    ) -> list[ApiSecurityEvent]:

        start_time = event.timestamp - timedelta(
            seconds=window_seconds
        )

        documents = events_collection.find(
            {
                "timestamp": {
                    "$gte": start_time,
                    "$lt": event.timestamp,
                },
                "network.source_ip": event.network.source_ip,
            }
        ).sort(
            "timestamp",
            -1
        )

        return [
            ApiSecurityEvent.model_validate(document)
            for document in documents
        ]