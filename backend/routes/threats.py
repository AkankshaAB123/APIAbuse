from collections import defaultdict

from fastapi import APIRouter, HTTPException

from backend.database import events_collection


router = APIRouter()


@router.get("/threats")
def get_threats():
    """
    Return all detected threats in a frontend-friendly format.
    """

    documents = events_collection.find(
        {
            "processing.risk_assessment.threat_detected": True
        }
    ).sort(
        "timestamp",
        -1
    )

    threats = []

    for document in documents:

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

        threats.append(
            {
                "id": document.get(
                    "event_id"
                ),

                "timestamp": document.get(
                    "timestamp"
                ),

                "sourceIp": document.get(
                    "network",
                    {}
                ).get(
                    "source_ip"
                ),

                "userId": document.get(
                    "identity",
                    {}
                ).get(
                    "user_id"
                ),

                "endpoint": document.get(
                    "request",
                    {}
                ).get(
                    "endpoint"
                ),

                "method": document.get(
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

                "threatDetected": risk_assessment.get(
                    "threat_detected",
                    False
                ),

                "detectorCount": risk_assessment.get(
                    "detector_count",
                    0
                ),

                "detectors": detector_results,
            }
        )

    return threats


@router.get("/threats/{event_id}")
def get_threat_by_id(event_id: str):
    """
    Return complete information about one threat event.
    """

    document = events_collection.find_one(
        {
            "event_id": event_id
        }
    )

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Threat event not found"
        )

    document["_id"] = str(
        document["_id"]
    )

    return document


@router.get("/statistics")
def get_statistics():
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