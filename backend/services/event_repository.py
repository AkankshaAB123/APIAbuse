from schemas.api_security_event import ApiSecurityEvent

from database import events_collection


class EventRepository:
    def save_event(self, event: ApiSecurityEvent):
        event_data = event.model_dump()

        events_collection.insert_one(event_data)

        return event_data