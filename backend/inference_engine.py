import logging
import math
import threading
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import pandas as pd

from ml.features.governance import CANONICAL_TRACKS, FLOW_FEATURES

logger = logging.getLogger(__name__)

SUPPORTED_TRACKS = list(CANONICAL_TRACKS)
FINGERPRINT_REQUIREMENT = {"B_JA3": "ja3_hash", "D_JA3_FLOW": "ja3_hash", "C_JA4": "ja4", "E_JA4_FLOW": "ja4"}
INFERENCE_TYPE_MODEL = "REGISTERED_RESEARCH_PILOT_MODEL"
INFERENCE_TYPE_NONE = "NOT_PERFORMED"
DEFAULT_THRESHOLD_KEY = "fpr<=0.01"


class InferenceMetrics:
    """Operational inference metrics measured in-process (not model-quality metrics)."""

    def __init__(self, window: int = 2000):
        self._lock = threading.Lock()
        self.latencies_ms: Deque[float] = deque(maxlen=window)
        self.by_status: Counter = Counter()
        self.by_track: Counter = Counter()
        self.skip_reasons: Counter = Counter()
        self.errors = 0
        self.started_at = time.time()

    def observe(self, track: str, status: str, latency_ms: float, skip_code: Optional[str] = None) -> None:
        with self._lock:
            self.by_status[status] += 1
            self.by_track[track] += 1
            if status == "COMPLETED":
                self.latencies_ms.append(latency_ms)
            if skip_code:
                self.skip_reasons[skip_code] += 1
            if status == "ERROR":
                self.errors += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            lat = sorted(self.latencies_ms)
            def q(p):
                return round(lat[min(len(lat) - 1, int(p * len(lat)))], 4) if lat else None
            total = sum(self.by_status.values())
            elapsed = max(time.time() - self.started_at, 1e-9)
            return {"total_requests": total, "by_status": dict(self.by_status), "by_track": dict(self.by_track),
                    "skip_reasons": dict(self.skip_reasons), "errors": self.errors,
                    "latency_ms": {"n": len(lat), "p50": q(0.5), "p95": q(0.95), "p99": q(0.99),
                                   "max": round(lat[-1], 4) if lat else None},
                    "requests_per_second_since_start": round(total / elapsed, 4),
                    "note": "Latency covers completed model inferences only (feature validation + scoring)."}


class InferenceEngine:
    """
    Real-time inference over models from the Phase 9 model registry.

    * Only ACTIVE, checksum-verified registry models are used (data/model_registry/registry.json).
    * Nothing is trained at import time and no ground-truth label is ever used to produce a score.
    * A flow is scored only if it carries every input column of the model's schema; a missing
      column, or a missing value for a feature that was never missing in training, produces
      status SKIPPED with reason INCOMPATIBLE_FEATURE_SCHEMA. No value is invented.
    * Tracks without an ACTIVE model return SKIPPED / NO_VALIDATED_MODEL.
    """

    def __init__(self, autoload: bool = True):
        self.model_name = "ETTH-ModelRegistry"
        # Kept for backward compatibility with callers that inspect the flow feature list.
        self.flow_stat_cols: List[str] = list(FLOW_FEATURES)
        self.models: Dict[str, Tuple[Dict[str, Any], Any]] = {}
        self.load_status: Dict[str, Dict[str, Any]] = {t: {"status": "NO_ACTIVE_MODEL"} for t in SUPPORTED_TRACKS}
        self.metrics = InferenceMetrics()
        self._lock = threading.Lock()
        self.is_initialized = False
        if autoload:
            self.reload()

    # ------------------------------------------------------------------ loading --
    def reload(self) -> Dict[str, Dict[str, Any]]:
        try:
            from ml import model_registry
            active = model_registry.active_models()
        except Exception as exc:
            logger.warning("Model registry unavailable: %s", exc)
            active = {}
            for t in SUPPORTED_TRACKS:
                self.load_status[t] = {"status": "REGISTRY_UNAVAILABLE", "error": str(exc)}
        models: Dict[str, Tuple[Dict[str, Any], Any]] = {}
        status: Dict[str, Dict[str, Any]] = {t: {"status": "NO_ACTIVE_MODEL"} for t in SUPPORTED_TRACKS}
        for track, entry in active.items():
            try:
                from ml import model_registry
                model = model_registry.load_model(entry)
                models[track] = (entry, model)
                status[track] = {"status": "LOADED", "model_id": entry["model_id"], "version": entry["version"],
                                 "research_status": entry.get("research_status"),
                                 "calibration": entry.get("calibration", {}).get("status")}
            except Exception as exc:
                status[track] = {"status": "LOAD_FAILED", "model_id": entry.get("model_id"),
                                 "version": entry.get("version"), "error": f"{type(exc).__name__}: {exc}"}
                logger.error("Refusing to load model for %s: %s", track, exc)
        with self._lock:
            self.models, self.load_status = models, status
            self.is_initialized = bool(models)
        return status

    def install(self, track: str, entry: Dict[str, Any], model: Any) -> None:
        """Programmatic installation (tests, controlled tooling). The entry must describe the model."""
        with self._lock:
            self.models[track] = (entry, model)
            self.load_status[track] = {"status": "LOADED", "model_id": entry.get("model_id"), "version": entry.get("version")}
            self.is_initialized = True

    def uninstall_all(self) -> None:
        with self._lock:
            self.models = {}
            self.load_status = {t: {"status": "NO_ACTIVE_MODEL"} for t in SUPPORTED_TRACKS}
            self.is_initialized = False

    def status(self) -> Dict[str, Any]:
        return {"tracks": self.load_status, "metrics": self.metrics.snapshot()}

    # ---------------------------------------------------------------- helpers --
    @staticmethod
    def _is_clean_value(val: Any) -> bool:
        if val is None:
            return False
        if isinstance(val, float) and math.isnan(val):
            return False
        s = str(val).strip()
        return s != "" and s.lower() not in ("none", "nan", "missing")

    def _result(self, track: str, status: str, prediction: str = "UNKNOWN", score: float = 0.0, confidence: float = 0.0,
                skip_reason: Optional[str] = None, evidence: Optional[List[str]] = None, entry: Optional[Dict[str, Any]] = None,
                inference_type: str = INFERENCE_TYPE_NONE, threshold: Optional[float] = None,
                ood: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            "prediction": prediction, "threat_score": score, "model_name": entry["estimator"] if entry else self.model_name,
            "confidence": confidence, "track": track, "status": status, "skip_reason": skip_reason,
            "evidence": evidence or [], "inference_type": inference_type,
            "model_id": entry.get("model_id") if entry else None, "model_version": entry.get("version") if entry else None,
            "research_status": entry.get("research_status") if entry else None,
            "calibration_status": (entry.get("calibration") or {}).get("status") if entry else None,
            "decision_threshold": threshold, "ood_flags": ood or [],
        }

    def _schema_problems(self, flow: Dict[str, Any], model: Any) -> List[str]:
        problems = []
        state = model.preprocessing["state"]
        for col, s in state["numeric"].items():
            if col not in flow:
                problems.append(f"{col}: absent")
                continue
            v = flow[col]
            missing = v is None or (isinstance(v, float) and math.isnan(v))
            if missing and not s.get("indicator"):
                problems.append(f"{col}: missing, but never missing in training")
            if not missing:
                try:
                    float(v)
                except (TypeError, ValueError):
                    problems.append(f"{col}: non-numeric value")
        for col in state["categorical"]:
            if col not in flow:
                problems.append(f"{col}: absent")
        if flow.get("live_feature_window_truncated") and any(c in state["numeric"] for c in FLOW_FEATURES):
            problems.append("live feature window truncated: flow statistics would differ from training semantics")
        return problems

    def _ood_flags(self, flow: Dict[str, Any], entry: Dict[str, Any]) -> List[str]:
        flags = []
        for col, q in (entry.get("ood_reference") or {}).get("numeric_quantiles", {}).items():
            v = flow.get(col)
            try:
                v = float(v)
            except (TypeError, ValueError):
                continue
            if math.isnan(v):
                continue
            if v < q["q005"] or v > q["q995"]:
                flags.append(f"OUT_OF_TRAINING_RANGE:{col}")
        for col, vocab in (entry.get("known_vocab") or {}).items():
            v = flow.get(col)
            if vocab is not None and self._is_clean_value(v) and str(v) not in set(vocab):
                flags.append(f"UNSEEN_CATEGORY:{col}")
        cap = flow.get("capture_id")
        if cap and cap in set((entry.get("training") or {}).get("captures", [])):
            flags.append("IN_SAMPLE_REPLAY:capture_used_in_training")
        return flags

    # ---------------------------------------------------------------- predict --
    def predict(self, flow: Dict[str, Any], track: str = "A_FLOW") -> Dict[str, Any]:
        t0 = time.perf_counter()
        if track not in SUPPORTED_TRACKS:
            res = self._result(track, "SKIPPED", skip_reason=f"Unsupported model track: '{track}'. Supported tracks: {SUPPORTED_TRACKS}",
                               evidence=[f"Requested track '{track}' is not supported by the ETTH pipeline."])
            self.metrics.observe(track, "SKIPPED", 0.0, "UNSUPPORTED_TRACK")
            return res

        fp_col = FINGERPRINT_REQUIREMENT.get(track)
        if fp_col and not self._is_clean_value(flow.get(fp_col)):
            name = "JA3" if fp_col == "ja3_hash" else "JA4"
            res = self._result(track, "SKIPPED", skip_reason=f"{name} fingerprint missing for requested track {track}",
                               evidence=[f"Model track {track} requires a valid {name} fingerprint.",
                                         f"{name} fingerprint is unavailable in this flow record; inference skipped to prevent data fabrication."])
            self.metrics.observe(track, "SKIPPED", 0.0, f"{name}_MISSING")
            return res

        with self._lock:
            loaded = self.models.get(track)
        if loaded is None:
            st = self.load_status.get(track, {}).get("status", "NO_ACTIVE_MODEL")
            res = self._result(track, "SKIPPED", skip_reason=f"NO_VALIDATED_MODEL: no ACTIVE registered model is loaded for track {track} ({st}).",
                               evidence=["No score is produced without a registered, checksum-verified model.",
                                         "Register and activate a model with `python -m ml train-deployable` / `python -m ml activate`."])
            self.metrics.observe(track, "SKIPPED", 0.0, "NO_VALIDATED_MODEL")
            return res

        entry, model = loaded
        problems = self._schema_problems(flow, model)
        if problems:
            shown = problems[:8]
            res = self._result(track, "SKIPPED", entry=entry,
                               skip_reason=f"INCOMPATIBLE_FEATURE_SCHEMA: {len(problems)} required input(s) unusable: {shown}"
                                           + (" ..." if len(problems) > 8 else ""),
                               evidence=[f"Model {entry['model_id']} v{entry['version']} requires {len(model.required_numeric)} numeric "
                                         f"and {len(model.required_categorical)} categorical inputs.",
                                         "Missing inputs are not imputed or invented; the flow was not scored."])
            self.metrics.observe(track, "SKIPPED", 0.0, "INCOMPATIBLE_FEATURE_SCHEMA")
            return res

        try:
            row = {c: flow.get(c) for c in model.required_numeric + model.required_categorical}
            for c in model.required_numeric:
                v = row[c]
                row[c] = float("nan") if v is None else float(v)
            score = float(model.predict_proba1(pd.DataFrame([row]))[0])
            thr = (entry.get("thresholds") or {}).get(DEFAULT_THRESHOLD_KEY)
            threshold = float(thr) if thr is not None else 0.5
            prediction = "MALICIOUS" if score >= threshold else "BENIGN"
            ood = self._ood_flags(flow, entry)
            evidence = [
                f"Model {entry['model_id']} v{entry['version']} ({entry['estimator']}, track {track}); status {entry.get('research_status')}.",
                f"Score {score:.4f} vs threshold {threshold:.4f} "
                + ("(selected on validation captures for FPR<=1%)." if thr is not None else "(default 0.5; no validation threshold stored)."),
                f"Calibration: {(entry.get('calibration') or {}).get('status', 'UNKNOWN')}. The score reflects similarity to the training captures, not a verified probability of maliciousness.",
            ]
            if "flow_duration" in row:
                evidence.append(f"Inputs used include flow_duration={flow.get('flow_duration')}, total_packets={flow.get('total_packets')}, total_bytes={flow.get('total_bytes')}.")
            for col in model.required_categorical:
                if col in ("ja3_hash", "ja4") and self._is_clean_value(flow.get(col)):
                    evidence.append(f"{col}={str(flow.get(col))[:40]} was part of the input.")
            if ood:
                evidence.append(f"Out-of-distribution warnings: {', '.join(ood[:6])}" + (" ..." if len(ood) > 6 else ""))
            latency = (time.perf_counter() - t0) * 1000.0
            self.metrics.observe(track, "COMPLETED", latency)
            return self._result(track, "COMPLETED", prediction=prediction, score=round(score, 6),
                                confidence=round(abs(score - threshold) / max(threshold, 1 - threshold), 4),
                                evidence=evidence, entry=entry, inference_type=INFERENCE_TYPE_MODEL, threshold=threshold, ood=ood)
        except Exception as exc:
            logger.warning("Inference error for track %s: %s", track, exc)
            self.metrics.observe(track, "ERROR", 0.0, "INFERENCE_ERROR")
            return self._result(track, "ERROR", entry=entry, skip_reason=f"INFERENCE_ERROR: {type(exc).__name__}: {exc}",
                                evidence=["The model raised an error; no score was produced."])


inference_engine = InferenceEngine()
