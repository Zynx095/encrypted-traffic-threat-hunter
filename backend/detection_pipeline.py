import logging
import datetime
import pandas as pd
from typing import Dict, Any, Optional

from backend.schemas import (
    ETTHStreamEvent,
    FlowDetails,
    TLSDetails,
    DetectionDetails,
    ProvenanceDetails
)
from backend.inference_engine import inference_engine
from backend.target_resolver import target_resolver

logger = logging.getLogger(__name__)

class DetectionPipeline:
    """
    Event-Driven ETTH Detection Pipeline.
    Orchestrates: Flow Input -> Target Attribution -> Feature Prep -> Fingerprint Check -> Track Routing -> Inference -> Evidence -> Canonical Event.
    """
    def __init__(self):
        self.caveat_text = (
            "Source-confounding limitation: DS-008 malicious vs DS-004 benign split. "
            "Pilot classification is an engineering demonstration and not generalized real-world malware detection performance."
        )

    def _clean_str(self, val: Any) -> Optional[str]:
        if pd.isnull(val) or val is None or str(val).strip() == "" or str(val).lower() in ["none", "nan", "missing"]:
            return None
        return str(val)

    def process_flow(
        self, 
        flow: Dict[str, Any], 
        track: str = "A_FLOW", 
        stream_id: str = "stream_default", 
        sequence: int = 1,
        mode: str = "REPLAY",
        target_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> ETTHStreamEvent:
        """
        Processes a single flow record and returns a validated ETTHStreamEvent.
        Isolates per-flow errors so stream playback is never interrupted by bad records.
        """
        flow_id = str(flow.get("flow_id", f"flow-{sequence}"))
        dataset_id = str(flow.get("dataset_id", "DS-008"))
        if dataset_id.lower() == "nan":
            dataset_id = "DS-008"

        ja3 = self._clean_str(flow.get("ja3_hash"))
        ja4 = self._clean_str(flow.get("ja4"))

        logger.info(
            f"[FLOW_RECEIVED] flow_id={flow_id} dataset={dataset_id} "
            f"mode={mode} track={track} target_id={target_id} session_id={session_id} ja3_avail={bool(ja3)} ja4_avail={bool(ja4)}"
        )

        try:
            # 1. Flow Details
            flow_details = FlowDetails(
                flow_id=flow_id,
                protocol=str(flow.get("protocol", "TCP")).upper() if str(flow.get("protocol", "TCP")).upper() in ["TCP", "UDP"] else "TCP",
                forward_endpoint=str(flow.get("forward_endpoint", "192.168.1.100:443")),
                reverse_endpoint=str(flow.get("reverse_endpoint", "10.0.0.5:52314")),
                duration=float(flow.get("flow_duration", 0.0)) if pd.notnull(flow.get("flow_duration")) else 0.0,
                total_packets=int(flow.get("total_packets", 0)) if pd.notnull(flow.get("total_packets")) else 0,
                total_bytes=int(flow.get("total_bytes", 0)) if pd.notnull(flow.get("total_bytes")) else 0,
                packets_per_second=float(flow.get("packets_per_second", 0.0)) if pd.notnull(flow.get("packets_per_second")) else 0.0,
                bytes_per_second=float(flow.get("bytes_per_second", 0.0)) if pd.notnull(flow.get("bytes_per_second")) else 0.0,
            )

            # 2. TLS Details
            sni_val = self._clean_str(flow.get("sni") or flow.get("server_name") or flow.get("sni_value"))
            tls_details = TLSDetails(
                clienthello_present=bool(flow.get("clienthello_present", True)),
                serverhello_present=bool(flow.get("serverhello_present", True)),
                ja3_hash=ja3,
                ja3s_hash=self._clean_str(flow.get("ja3s_hash")),
                ja4=ja4,
                sni_present=bool(flow.get("sni_present", bool(sni_val))),
                sni_value=sni_val,
                alpn=self._clean_str(flow.get("alpn_value")),
            )

            # 3. Target Attribution Evaluation (Phase 7.6)
            attribution_details = target_resolver.resolve(
                flow=flow,
                tls_details=tls_details,
                target_id=target_id,
                session_id=session_id
            )

            import time
            t_start = time.perf_counter()

            # 4. Model Track Routing & Inference
            t_inf_start = time.perf_counter()
            inf_res = inference_engine.predict(flow, track=track)
            t_inf_end = time.perf_counter()
            inf_duration_ms = (t_inf_end - t_inf_start) * 1000.0

            if inf_res["status"] == "SKIPPED":
                logger.info(f"[INFERENCE_SKIPPED] flow_id={flow_id} track={track} reason='{inf_res['skip_reason']}'")
            else:
                logger.info(f"[INFERENCE_COMPLETED] flow_id={flow_id} track={track} prediction={inf_res['prediction']} score={inf_res['threat_score']}")

            detection_details = DetectionDetails(
                prediction=inf_res["prediction"],
                threat_score=inf_res["threat_score"],
                model_name=inf_res["model_name"],
                confidence=inf_res["confidence"],
                track=inf_res["track"],
                status=inf_res["status"],
                skip_reason=inf_res["skip_reason"],
                evidence=inf_res["evidence"],
                inference_type=inf_res["inference_type"]
            )

            # 5. Provenance Details
            provenance_details = ProvenanceDetails(
                dataset_id=dataset_id,
                source_file=self._clean_str(flow.get("source_file")),
                label_ground_truth=str(flow.get("label", "UNKNOWN")).upper(),
                caveat=self.caveat_text
            )

            event_id = f"evt_{stream_id}_{sequence:05d}"
            timestamp = datetime.datetime.utcnow().isoformat() + "Z"

            event = ETTHStreamEvent(
                event_id=event_id,
                sequence=sequence,
                timestamp=timestamp,
                stream_id=stream_id,
                target_id=target_id or attribution_details.target_id,
                session_id=session_id,
                source=dataset_id,
                mode=mode,
                event_type="flow.detected",
                flow=flow_details,
                tls=tls_details,
                attribution=attribution_details,
                detection=detection_details,
                provenance=provenance_details
            )
            setattr(event, "_proc_duration_ms", (time.perf_counter() - t_start) * 1000.0)
            setattr(event, "_inf_duration_ms", inf_duration_ms)

            logger.info(f"[EVENT_EMITTED] event_id={event_id} seq={sequence} mode={mode} event_type=flow.detected attribution={attribution_details.status}")
            return event


        except Exception as e:
            logger.error(f"[PIPELINE_ERROR] Error processing flow_id={flow_id}: {e}", exc_info=True)
            
            # Error isolation fallback event
            fallback_event = ETTHStreamEvent(
                event_id=f"evt_{stream_id}_{sequence:05d}_err",
                sequence=sequence,
                timestamp=datetime.datetime.utcnow().isoformat() + "Z",
                stream_id=stream_id,
                target_id=target_id,
                session_id=session_id,
                source=dataset_id,
                mode=mode,
                event_type="flow.detected",
                flow=FlowDetails(
                    flow_id=flow_id,
                    forward_endpoint="0.0.0.0:0",
                    reverse_endpoint="0.0.0.0:0"
                ),
                tls=TLSDetails(),
                detection=DetectionDetails(
                    prediction="UNKNOWN",
                    threat_score=0.0,
                    track=track if track in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"] else "A_FLOW",
                    status="ERROR",
                    skip_reason=f"Pipeline processing error: {str(e)}",
                    evidence=[f"Per-flow processing exception: {str(e)}"]
                ),
                provenance=ProvenanceDetails(
                    dataset_id=dataset_id,
                    caveat=self.caveat_text
                )
            )
            return fallback_event

detection_pipeline = DetectionPipeline()
