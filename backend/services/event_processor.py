from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.processing_result import ProcessingResult

from backend.services.detection_service import DetectionService
from backend.services.event_repository import EventRepository
from backend.services.ml_service import MLService
from backend.services.risk_engine import RiskEngine
from backend.services.mitigation_service import MitigationService

from rag.analysis.rag_service import analyze_threat


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

        print(
            "\n================ EVENT PROCESSING START ================"
        )

        print(
            f"[1] Event received: {event.event_id}"
        )


        # ====================================================
        # MONGODB - RECENT EVENTS
        # ====================================================

        print(
            "[2] Checking recent events in MongoDB..."
        )

        recent_events = (
            self.repository.get_recent_events(
                event
            )
        )

        print(
            "[3] Recent events retrieved."
        )


        # ====================================================
        # SAVE EVENT
        # ====================================================

        print(
            "[4] Saving event to MongoDB..."
        )

        self.repository.save_event(
            event
        )

        print(
            "[5] Event saved successfully."
        )


        # ====================================================
        # API ABUSE DETECTION
        # ====================================================

        print(
            "[6] Running API abuse detectors..."
        )

        detector_results = (
            self.detection_service.detect(
                event,
                recent_events,
            )
        )

        print(
            f"[7] Detection completed. "
            f"Results: {len(detector_results)}"
        )


        # ====================================================
        # ML DETECTION
        # ====================================================

        ml_result = None

        if ml_features:

            print(
                "[8] ML features supplied. Running ML detection..."
            )

            ml_result = self.ml_service.detect(
                ml_features
            )

        else:

            print(
                "[8] No ML features supplied. Skipping ML."
            )


        # ====================================================
        # RISK ENGINE
        # ====================================================

        print(
            "[10] Calculating risk score..."
        )

        risk_assessment = (
            self.risk_engine.assess(
                event_id=event.event_id,
                detector_results=detector_results,
                ml_result=ml_result,
            )
        )

        print(
            f"[11] Risk calculated: "
            f"{risk_assessment.risk_score} "
            f"({risk_assessment.risk_level})"
        )


        # ====================================================
        # MITIGATION
        # ====================================================

        print(
            "[12] Deciding mitigation action..."
        )

        mitigation_action = (
            self.mitigation_service.decide_action(
                risk_assessment
            )
        )

        print(
            f"[13] Mitigation action: "
            f"{mitigation_action}"
        )


        # ====================================================
        # RAG + GEMINI
        # ====================================================

        ai_analysis = None

        if risk_assessment.threat_detected:

            print(
                "[14] Threat detected."
            )

            print(
                "[15] Starting RAG + Gemini analysis..."
            )


            try:

                # --------------------------------------------
                # Find first detected API detector
                # --------------------------------------------

                detected_result = next(
                    (
                        result
                        for result in detector_results
                        if result.detected
                    ),
                    None,
                )


                # --------------------------------------------
                # Determine attack type and severity
                # --------------------------------------------

                if detected_result is not None:

                    attack_type = (
                        detected_result.attack_type
                        or "Unknown"
                    )

                    severity = (
                        detected_result.severity
                        or risk_assessment.risk_level
                    )

                    # ----------------------------------------
                    # IMPORTANT:
                    # Extract the ACTUAL detector evidence
                    # ----------------------------------------

                    evidence = [
                        {
                            "code": item.code,
                            "message": item.message,
                        }
                        for item in detected_result.evidence
                    ]

                else:

                    attack_type = (
                        risk_assessment.attack_types[0]
                        if risk_assessment.attack_types
                        else "Unknown"
                    )

                    severity = (
                        risk_assessment.risk_level
                    )

                    evidence = []


                print(
                    f"[16] RAG attack type: "
                    f"{attack_type}"
                )

                print(
                    f"[17] Detector evidence: "
                    f"{evidence}"
                )


                # --------------------------------------------
                # Build threat event for RAG
                # --------------------------------------------

                threat_event = {

                    "attack_type": attack_type,

                    "endpoint": (
                        event.request.endpoint
                    ),

                    "method": (
                        event.request.method
                    ),

                    "source_ip": (
                        event.network.source_ip
                    ),

                    "risk_score": (
                        risk_assessment.risk_score
                    ),

                    "severity": severity,

                    "evidence": evidence,
                }


                print(
                    "[18] Calling RAG service..."
                )


                rag_result = analyze_threat(
                    threat_event
                )


                print(
                    "[19] RAG + Gemini analysis completed."
                )


                ai_analysis = rag_result


            except Exception as exc:

                print(
                    f"[RAG ERROR] "
                    f"RAG/Gemini analysis failed: {exc}"
                )

                ai_analysis = {
                    "error": "AI analysis unavailable"
                }


        else:

            print(
                "[14] No threat detected. "
                "Skipping RAG + Gemini."
            )


        # ====================================================
        # BUILD PROCESSING RESULT
        # ====================================================

        print(
            "[20] Building processing result..."
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

            ai_analysis=ai_analysis,
        )


        # ====================================================
        # UPDATE MONGODB
        # ====================================================

        print(
            "[21] Updating MongoDB with processing result..."
        )

        self.repository.update_processing_result(
            event.event_id,
            processing_result,
        )

        print(
            "[22] MongoDB update completed."
        )

        print(
            "================ EVENT PROCESSING END ================\n"
        )


        return processing_result