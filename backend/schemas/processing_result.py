from pydantic import BaseModel


class ProcessingResult(BaseModel):
    event_id: str
    status: str
    message: str