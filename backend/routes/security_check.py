from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    NetworkInfo,
    IdentityInfo,
    RequestInfo,
    ResponseInfo,
    ResourceInfo,
)
from backend.services.event_processor import EventProcessor


router = APIRouter()

processor = EventProcessor()


# =========================================================
# REQUEST MODEL
# =========================================================

class SecurityCheckRequest(BaseModel):

    endpoint: str = Field(
        ...,
        min_length=1,
        description="API URL or endpoint to assess"
    )

    method: str = Field(
        default="GET",
        description="HTTP method used by the API request"
    )

    authentication: bool = Field(
        default=True,
        description="Whether authentication is required"
    )

    sensitive: bool = Field(
        default=False,
        description="Whether the API handles sensitive data"
    )


# =========================================================
# API SECURITY CHECK
# =========================================================

@router.post("/security-check")
def security_check(
    request: SecurityCheckRequest
):

    try:

        event_id = (
            f"SECURITY-CHECK-{uuid4()}"
        )


        # -------------------------------------------------
        # Build an internal security event
        #
        # We only populate information that the user
        # actually supplied or that is safe to treat as
        # neutral system metadata.
        # -------------------------------------------------

        event = ApiSecurityEvent(

            schema_version="1.0",

            event_id=event_id,

            timestamp=datetime.now(
                timezone.utc
            ),

            # -------------------------------------------------
            # Network information
            #
            # The Enterprise assessment does not ask the user
            # for an IP address, so we use a neutral local value.
            # -------------------------------------------------

            network=NetworkInfo(

                source_ip="127.0.0.1",

                user_agent="API-Security-Assessment"

            ),

            # -------------------------------------------------
            # Identity information
            #
            # We do NOT invent a user ID or session ID.
            # -------------------------------------------------

            identity=IdentityInfo(

                user_id=None,

                session_id=None,

                roles=[],

                is_authenticated=(
                    request.authentication
                )

            ),

            # -------------------------------------------------
            # Request information
            # -------------------------------------------------

            request=RequestInfo(

                method=request.method.upper(),

                endpoint=request.endpoint,

                path_params={},

                query_params={},

                headers={},

                body=None

            ),

            # -------------------------------------------------
            # Response information
            #
            # No real external API request is being made by
            # this assessment endpoint yet.
            # -------------------------------------------------

            response=ResponseInfo(

                status_code=200,

                latency_ms=0

            ),

            # -------------------------------------------------
            # Resource information
            #
            # We don't know the resource ID or owner from the
            # simplified Enterprise form, so they remain None.
            # -------------------------------------------------

            resource=ResourceInfo(

                resource_type="API_RESOURCE",

                resource_id=None,

                owner_id=None,

                is_sensitive=(
                    request.sensitive
                )

            )

        )


        # -------------------------------------------------
        # Run existing detection + risk + mitigation + RAG
        # -------------------------------------------------

        result = processor.process(
            event=event
        )


        # -------------------------------------------------
        # Build response for frontend
        # -------------------------------------------------

        return {

            "success": True,

            "event_id": result.event_id,

            "status": result.status,

            "message": result.message,

            "security_score": (

                result.risk_assessment.risk_score

                if result.risk_assessment

                else 0

            ),

            "risk_level": (

                result.risk_assessment.risk_level

                if result.risk_assessment

                else "LOW"

            ),

            "threat_detected": (

                result.risk_assessment.threat_detected

                if result.risk_assessment

                else False

            ),

            "attack_types": (

                result.risk_assessment.attack_types

                if result.risk_assessment

                else []

            ),

            "reasons": (

                result.risk_assessment.reasons

                if result.risk_assessment

                else []

            ),

            "mitigation_action":

                result.mitigation_action,

            "detector_results": [

                detector.model_dump()

                for detector
                in result.detector_results

            ],

            "ai_analysis":

                result.ai_analysis

        }


    except Exception as exc:

        print(
            f"[SECURITY CHECK ERROR] {exc}"
        )

        raise HTTPException(

            status_code=500,

            detail=(
                "Security assessment failed"
            )

        ) from exc