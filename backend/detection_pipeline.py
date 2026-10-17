import logging
import datetime
import pandas as pd
from typing import Dict, Any, Optional

from backend.schemas import (
    ETTHStreamEvent,
    FlowDetails,
    TLSDetails,
    DetectionDetails,
    ProvenanceDetails,
    SensorContext
)
from pipeline.canonical_flow import unobserved_fields
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
            "Research pilot: models are trained on exploratory, source-confounded captures (one class per dataset: "
            "DS-008/DS-009 malicious, DS-011 benign). Scores are not generalized real-world malware detection performance."
        )

    def _clean_str(self, val: Any) -> Optional[str]:
        if pd.isnull(val) or val is None or str(val).strip() == "" or str(val).lower() in ["none", "nan", "missing"]:
            return None
        return str(val)

    def _sensor_context(self, flow: Dict[str, Any]) -> Optional[SensorContext]:
        sensor_type = self._clean_str(flow.get("sensor_type"))
        if not sensor_type:
            return None
        alerts = flow.get("sensor_alerts")
        return SensorContext(
            sensor_type=sensor_type,
            sensor_record_id=self._clean_str(flow.get("sensor_record_id")),
            feature_provenance=self._clean_str(flow.get("feature_provenance")),
            byte_count_semantics=self._clean_str(flow.get("byte_count_semantics")),
            ja4_implementation=self._clean_str(flow.get("ja4_implementation")),
            tls_version_observed=self._clean_str(flow.get("tls_version_observed")),
            tls_version_semantics=self._clean_str(flow.get("tls_version_semantics")),
            alpn_negotiated=self._clean_str(flow.get("alpn_negotiated")),
            external_alert_signatures=[str(a) for a in alerts if a] if isinstance(alerts, list) else [],
        )

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
        dataset_id = str(flow.get("dataset_id") or "UNKNOWN")
        if dataset_id.lower() == "nan":
            dataset_id = "UNKNOWN"

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
                # Endpoints are reported only when observed; no placeholder addresses are invented.
                forward_endpoint=str(flow.get("forward_endpoint") or "UNKNOWN"),
                reverse_endpoint=str(flow.get("reverse_endpoint") or "UNKNOWN"),
                duration=float(flow.get("flow_duration", 0.0)) if pd.notnull(flow.get("flow_duration")) else 0.0,
                total_packets=int(flow.get("total_packets", 0)) if pd.notnull(flow.get("total_packets")) else 0,
                total_bytes=int(flow.get("total_bytes", 0)) if pd.notnull(flow.get("total_bytes")) else 0,
                packets_per_second=float(flow.get("packets_per_second", 0.0)) if pd.notnull(flow.get("packets_per_second")) else 0.0,
                bytes_per_second=float(flow.get("bytes_per_second", 0.0)) if pd.notnull(flow.get("bytes_per_second")) else 0.0,
                unobserved_fields=unobserved_fields(flow)
                + ([] if str(flow.get("protocol", "")).upper() in ("TCP", "UDP") else ["protocol"]),
            )

            # 2. TLS Details
            sni_val = self._clean_str(flow.get("sni") or flow.get("server_name") or flow.get("sni_value"))
            tls_details = TLSDetails(
                clienthello_present=bool(flow.get("clienthello_present") or False),
                serverhello_present=bool(flow.get("serverhello_present") or False),
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
                **{k: v for k, v in inf_res.items() if k in DetectionDetails.model_fields}
            )

            # 5. Provenance Details
            provenance_details = ProvenanceDetails(
                dataset_id=dataset_id,
                source_file=self._clean_str(flow.get("source_file")),
                label_ground_truth=str(flow.get("label", "UNKNOWN")).upper(),
                caveat=self.caveat_text,
                sensor=self._sensor_context(flow),
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
                    forward_endpoint="UNKNOWN",
                    reverse_endpoint="UNKNOWN",
                    unobserved_fields=["forward_endpoint", "reverse_endpoint", "flow_duration", "total_packets",
                                       "total_bytes", "packets_per_second", "bytes_per_second"],
                ),
                tls=TLSDetails(),
                detection=DetectionDetails(
                    prediction="UNKNOWN",
                    threat_score=0.0,
                    track=track if track in ["A_FLOW", "B_JA3", "C_JA4", "D_JA3_FLOW", "E_JA4_FLOW"] else "A_FLOW",
                    status="ERROR",
                    # Exception text can contain paths or data; clients get the type only (details are logged).
                    skip_reason=f"PIPELINE_ERROR: {type(e).__name__} while processing this flow (details in the server log)",
                    evidence=["Per-flow processing failed; no score was produced and the stream continues."]
                ),
                provenance=ProvenanceDetails(
                    dataset_id=dataset_id,
                    caveat=self.caveat_text
                )
            )
            return fallback_event

detection_pipeline = DetectionPipeline()
