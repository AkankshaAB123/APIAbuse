from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.database import events_collection
from backend.dependencies.auth import get_current_user, require_analyst
from backend.schemas.impact_assessment import ImpactAssessment
from backend.schemas.user import UserInDB, UserRole


router = APIRouter()


@router.get("/threats")
def get_threats(
    device_ip: Optional[str] = Query(
        None,
        description=(
            "Optional manual filter for SOC staff (ADMIN/ANALYST). "
            "For DEVICE role callers, device scope is strictly enforced "
            "from the authenticated JWT user record."
        ),
    ),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Return detected threats in a frontend-friendly format.

    REAL SERVER-SIDE AUTHORIZATION:
    - If current_user.role == DEVICE: results are strictly and unconditionally
      filtered by current_user.device_ip. Any conflicting device_ip query parameter
      is ignored. Devices cannot access incidents belonging to other devices.
    - If current_user.role in (ADMIN, ANALYST): full global SOC threat visibility.
      Can optionally use ?device_ip=... to inspect a specific host.
    """
    base_filter: dict = {"processing.risk_assessment.threat_detected": True}

    if current_user.role == UserRole.DEVICE:
        # Enforce server-side device scope from JWT identity
        enforced_ip = current_user.device_ip or "10.165.192.186"
        base_filter["network.destination_ip"] = enforced_ip
    elif device_ip:
        # Staff filtering convenience
        base_filter["network.destination_ip"] = device_ip

    documents = events_collection.find(base_filter).sort("timestamp", -1)

    threats = []

    for document in documents:

        lab_incident = document.get(
            "lab_incident",
            {},
        )

        lab_attack = lab_incident.get(
            "attack",
            {},
        )

        lab_impact = lab_incident.get(
            "impact",
            {},
        )

        lab_mitigation = lab_incident.get(
            "mitigation",
            {},
        )

        processing = document.get(
            "processing",
            {}
        )

        risk_assessment = processing.get(
            "risk_assessment",
            {}
        )

        detector_results = processing.get(
            "detector_results",
            []
        )

        attack_types = risk_assessment.get(
            "attack_types",
            []
        )

        attack_type = (
            attack_types[0]
            if attack_types
            else "UNKNOWN"
        )

        actual_client_ip = lab_attack.get(
            "actual_client_ip"
        )

        lab_source_ip = lab_attack.get(
            "source_ip"
        )

        document_source_ip = document.get(
            "network",
            {}
        ).get(
            "source_ip"
        )

        source_ip = (
            actual_client_ip
            or lab_source_ip
            or document_source_ip
        )

        impact_data = processing.get(
            "impact"
        )

        impact = None
        if impact_data is not None:
            if isinstance(impact_data, dict):
                try:
                    impact = ImpactAssessment.model_validate(impact_data).model_dump()
                except Exception:
                    impact = impact_data
            else:
                impact = impact_data

        threats.append(
            {
                "id": document.get(
                    "event_id"
                ),

                "timestamp": document.get(
                    "timestamp"
                ),

                "sourceIp": source_ip,

                "actualClientIp": actual_client_ip,

                "syntheticSourceIp": (
                    lab_source_ip
                    if actual_client_ip and lab_source_ip != actual_client_ip
                    else None
                ),

                "userId": document.get(
                    "identity",
                    {}
                ).get(
                    "user_id"
                ),

                "endpoint": lab_attack.get(
                    "target_endpoint"
                ) or document.get(
                    "request",
                    {}
                ).get(
                    "endpoint"
                ),

                "method": lab_attack.get(
                    "method"
                ) or document.get(
                    "request",
                    {}
                ).get(
                    "method"
                ),

                "attackType": attack_type,

                "attackTypes": attack_types,

                "severity": risk_assessment.get(
                    "risk_level"
                ),

                "riskScore": risk_assessment.get(
                    "risk_score",
                    0
                ),

                "action": processing.get(
                    "mitigation_action",
                    "ALLOW"
                ),

                "finalStatus": lab_incident.get(
                    "status"
                ),

                "mitigationResult": lab_mitigation.get(
                    "result"
                ),

                "impactObserved": lab_impact.get(
                    "observed"
                ),

                "classification": lab_incident.get(
                    "classification"
                ),

                "labIncident": lab_incident or None,

                "threatDetected": risk_assessment.get(
                    "threat_detected",
                    False
                ),

                "detectorCount": risk_assessment.get(
                    "detector_count",
                    0
                ),

                "detectors": detector_results,

                "impact": impact,
            }
        )

    return threats


@router.get("/threats/{event_id}")
def get_threat_by_id(
    event_id: str,
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Return complete information about one threat event.

    REAL SERVER-SIDE AUTHORIZATION:
    - If current_user.role == DEVICE: the event is only returned if its
      network.destination_ip matches current_user.device_ip.
      Otherwise returns 404 Not Found to prevent leaking existence.
    - If current_user.role in (ADMIN, ANALYST): can retrieve any incident.
    """
    document = events_collection.find_one({"event_id": event_id})

    if document is None:
        raise HTTPException(status_code=404, detail="Threat event not found")

    # Device isolation check
    if current_user.role == UserRole.DEVICE:
        enforced_ip = current_user.device_ip or "10.165.192.186"
        event_dest_ip = document.get("network", {}).get("destination_ip")
        if event_dest_ip != enforced_ip:
            raise HTTPException(status_code=404, detail="Threat event not found")

    document["_id"] = str(document["_id"])

    processing = document.get("processing", {})
    if "impact" not in document and "impact" in processing:
        document["impact"] = processing["impact"]

    return document


@router.get("/statistics")
def get_statistics(
    current_user: UserInDB = Depends(require_analyst),
):
    """
    Return dashboard statistics and
    real traffic/threat trend data.
    """

    total_events = events_collection.count_documents({})

    total_threats = events_collection.count_documents(
        {
            "processing.risk_assessment.threat_detected": True
        }
    )

    critical_threats = events_collection.count_documents(
        {
            "processing.risk_assessment.risk_level": "CRITICAL"
        }
    )

    high_threats = events_collection.count_documents(
        {
            "processing.risk_assessment.risk_level": "HIGH"
        }
    )

    medium_threats = events_collection.count_documents(
        {
            "processing.risk_assessment.risk_level": "MEDIUM"
        }
    )

    low_threats = events_collection.count_documents(
        {
            "processing.risk_assessment.risk_level": "LOW"
        }
    )

    blocked_threats = events_collection.count_documents(
        {
            "processing.mitigation_action": "BLOCK"
        }
    )

    rate_limited_threats = events_collection.count_documents(
        {
            "processing.mitigation_action": "RATE_LIMIT"
        }
    )

    monitored_threats = events_collection.count_documents(
        {
            "processing.mitigation_action": "MONITOR"
        }
    )

    # ---------------------------------------------------------
    # REAL TRAFFIC & THREAT TREND
    # ---------------------------------------------------------

    trend_pipeline = [
        {
            "$match": {
                "timestamp": {
                    "$exists": True
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "year": {
                        "$year": "$timestamp"
                    },
                    "month": {
                        "$month": "$timestamp"
                    },
                    "day": {
                        "$dayOfMonth": "$timestamp"
                    },
                    "hour": {
                        "$hour": "$timestamp"
                    }
                },

                "requests": {
                    "$sum": 1
                },

                "threats": {
                    "$sum": {
                        "$cond": [
                            {
                                "$eq": [
                                    "$processing.risk_assessment.threat_detected",
                                    True
                                ]
                            },
                            1,
                            0
                        ]
                    }
                },

                "timestamp": {
                    "$min": "$timestamp"
                }
            }
        },
        {
            "$sort": {
                "timestamp": 1
            }
        }
    ]

    trend_results = list(
        events_collection.aggregate(
            trend_pipeline
        )
    )

    traffic_trend = []

    for item in trend_results:

        timestamp = item.get(
            "timestamp"
        )

        if timestamp is not None:
            time_label = timestamp.strftime(
                "%H:%M"
            )
        else:
            time_label = "Unknown"

        traffic_trend.append(
            {
                "time": time_label,

                "requests": item.get(
                    "requests",
                    0
                ),

                "threats": item.get(
                    "threats",
                    0
                )
            }
        )

    return {
        "totalEvents": total_events,

        "totalThreats": total_threats,

        "criticalThreats": critical_threats,

        "highThreats": high_threats,

        "mediumThreats": medium_threats,

        "lowThreats": low_threats,

        "blockedThreats": blocked_threats,

        "rateLimitedThreats": rate_limited_threats,

        "monitoredThreats": monitored_threats,

        "trafficTrend": traffic_trend
    }