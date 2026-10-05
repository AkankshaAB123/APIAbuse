from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from typing import Any
import json
import uuid
from datetime import datetime, timezone

from backend.services.event_processor import EventProcessor
from backend.schemas.api_security_event import ApiSecurityEvent, RequestInfo, NetworkInfo, IdentityInfo, ResourceInfo, ResponseInfo

router = APIRouter()
processor = EventProcessor()

@router.get("/workshop/xss-demo")
@router.post("/workshop/xss-demo")
async def xss_demo_endpoint(request: Request):
    """
    Isolated vulnerable demonstration endpoint for XSS.
    Returns the HTML rendering the payload, and also runs the IDS processor on the request.
    """
    
    # 1. Extract payload
    method = request.method
    query_params = dict(request.query_params)
    
    body = {}
    if method == "POST":
        try:
            body_bytes = await request.body()
            if body_bytes:
                body = json.loads(body_bytes.decode('utf-8'))
        except Exception:
            pass

    # Find payload to reflect
    payload_val = ""
    if method == "GET" and query_params:
        payload_val = next(iter(query_params.values()), "")
    elif method == "POST" and body:
        if isinstance(body, dict):
            payload_val = next(iter(body.values()), "")
        else:
            payload_val = str(body)
            
    # Vulnerable HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Sandbox</title>
        <style>body {{ font-family: sans-serif; padding: 20px; }}</style>
    </head>
    <body>
        <h3>Search Results for: {payload_val}</h3>
        <p>No results found.</p>
    </body>
    </html>
    """
    
    # 2. Build Event
    event_id = f"XSS-DEMO-{uuid.uuid4().hex[:8]}"
    
    event = ApiSecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        network=NetworkInfo(source_ip=request.client.host if request.client else "127.0.0.1"),
        identity=IdentityInfo(user_id="workshop_user", is_authenticated=True),
        request=RequestInfo(
            method=method,
            endpoint=request.url.path,
            query_params=query_params,
            body=body,
            headers=dict(request.headers)
        ),
        response=ResponseInfo(status_code=200, latency_ms=10.0),
        resource=ResourceInfo(resource_type="search", resource_id="sandbox")
    )
    
    # 3. Process Event through IDS
    processing_result = processor.process(event=event)
    
    # 4. Return both the HTML and the IDS result (so the frontend can display them)
    return {
        "html": html_content,
        "result": processing_result.dict() if hasattr(processing_result, "dict") else processing_result.__dict__
    }
