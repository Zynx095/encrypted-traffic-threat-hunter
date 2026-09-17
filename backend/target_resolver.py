import time
import threading
import logging
from typing import Dict, Any, List, Optional

from backend.schemas import (
    TargetAttribution,
    AttributionEvidence,
    TLSDetails
)
from backend.repositories import target_repository

logger = logging.getLogger(__name__)

class DNSObservation:
    """
    Time-aware normalized DNS observation record.
    """
    def __init__(self, hostname: str, resolved_ip: str, ttl: int = 300, source: str = "dns_capture"):
        self.hostname = hostname.strip().lower().rstrip('.')
        self.resolved_ip = resolved_ip.strip()
        self.ttl = max(1, ttl)
        self.source = source
        self.timestamp = time.time()

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time or time.time()
        return (now - self.timestamp) > self.ttl

class DNSCache:
    """
    Bounded, thread-safe, time-aware in-memory DNS correlation cache.
    Does not perform active network DNS lookup; consumes local observations.
    """
    def __init__(self, max_entries: int = 10000, default_ttl: int = 300):
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        # Maps hostname -> List[DNSObservation]
        self._host_map: Dict[str, List[DNSObservation]] = {}
        # Maps IP -> List[DNSObservation]
        self._ip_map: Dict[str, List[DNSObservation]] = {}

    def add_observation(self, hostname: str, resolved_ip: str, ttl: Optional[int] = None, source: str = "dns_capture") -> None:
        if not hostname or not resolved_ip:
            return
        clean_host = hostname.strip().lower().rstrip('.')
        clean_ip = resolved_ip.strip()
        eff_ttl = ttl if (ttl is not None and ttl > 0) else self.default_ttl

        obs = DNSObservation(hostname=clean_host, resolved_ip=clean_ip, ttl=eff_ttl, source=source)

        with self._lock:
            # Enforce max capacity eviction if needed
            if len(self._host_map) >= self.max_entries:
                # Evict expired or oldest entry
                self._evict_stale_locked()

            # Host map update
            if clean_host not in self._host_map:
                self._host_map[clean_host] = []
            self._host_map[clean_host] = [o for o in self._host_map[clean_host] if o.resolved_ip != clean_ip and not o.is_expired()]
            self._host_map[clean_host].append(obs)

            # IP map update
            if clean_ip not in self._ip_map:
                self._ip_map[clean_ip] = []
            self._ip_map[clean_ip] = [o for o in self._ip_map[clean_ip] if o.hostname != clean_host and not o.is_expired()]
            self._ip_map[clean_ip].append(obs)

    def _evict_stale_locked(self) -> None:
        now = time.time()
        for host in list(self._host_map.keys()):
            self._host_map[host] = [o for o in self._host_map[host] if not o.is_expired(now)]
            if not self._host_map[host]:
                del self._host_map[host]

        for ip in list(self._ip_map.keys()):
            self._ip_map[ip] = [o for o in self._ip_map[ip] if not o.is_expired(now)]
            if not self._ip_map[ip]:
                del self._ip_map[ip]

    def get_resolved_ips(self, hostname: str) -> List[str]:
        clean_host = hostname.strip().lower().rstrip('.')
        now = time.time()
        with self._lock:
            if clean_host not in self._host_map:
                return []
            active = [o for o in self._host_map[clean_host] if not o.is_expired(now)]
            self._host_map[clean_host] = active
            return [o.resolved_ip for o in active]

    def get_hostnames_for_ip(self, ip: str) -> List[str]:
        clean_ip = ip.strip()
        now = time.time()
        with self._lock:
            if clean_ip not in self._ip_map:
                return []
            active = [o for o in self._ip_map[clean_ip] if not o.is_expired(now)]
            self._ip_map[clean_ip] = active
            return [o.hostname for o in active]

    def clear(self) -> None:
        with self._lock:
            self._host_map.clear()
            self._ip_map.clear()

class TargetResolver:
    """
    ETTH Target Attribution Engine (Phase 7.6).
    Evaluates observable flow metadata against target definitions and time-aware DNS correlation.
    Strictly decoupled from maliciousness classification.
    """
    def __init__(self):
        self.version = "7.6.1"
        self.dns_cache = DNSCache()

    def normalize_hostname(self, hostname: Optional[str]) -> Optional[str]:
        if not hostname or not isinstance(hostname, str):
            return None
        clean = hostname.strip().lower().rstrip('.')
        if not clean or clean in ["none", "nan", "missing"]:
            return None
        try:
            # Handle IDNA punycode normalization
            if clean.startswith("xn--") or any(ord(c) > 127 for c in clean):
                clean = clean.encode("idna").decode("ascii").lower()
        except Exception:
            pass
        return clean

    def is_subdomain_match(self, sni_host: str, target_host: str) -> bool:
        """
        Validates subdomain relationship.
        Rejects suffix spoofs like 'youtube.com.evil.example'.
        """
        sni = self.normalize_hostname(sni_host)
        tgt = self.normalize_hostname(target_host)
        if not sni or not tgt:
            return False

        if sni == tgt:
            return True
        if sni.endswith("." + tgt):
            return True
        return False

    def _extract_dst_ip(self, flow: Dict[str, Any]) -> Optional[str]:
        # Try direct destination_ip / dst_ip field
        dst = flow.get("destination_ip") or flow.get("dst_ip") or flow.get("dest_ip")
        if dst:
            return str(dst).strip()
        # Parse from reverse_endpoint or forward_endpoint (e.g. "172.217.14.206:443")
        endpoint = flow.get("reverse_endpoint") or flow.get("forward_endpoint")
        if endpoint and isinstance(endpoint, str) and ":" in endpoint:
            ip_part = endpoint.split(":")[0].strip()
            if ip_part and ip_part != "0.0.0.0":
                return ip_part
        return None

    def resolve(
        self,
        flow: Dict[str, Any],
        tls_details: Optional[TLSDetails] = None,
        target_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> TargetAttribution:
        """
        Determines target attribution status, confidence, and structured evidence.
        """
        sni = None
        if tls_details and tls_details.sni_present:
            # Check custom field or fallback
            sni = getattr(tls_details, "sni_value", None)
        if not sni:
            sni = flow.get("sni") or flow.get("server_name") or flow.get("sni_value")
        sni_clean = self.normalize_hostname(sni)

        dst_ip = self._extract_dst_ip(flow)

        # 1. Target-scoped evaluation (when session target_id is specified)
        if target_id:
            target = target_repository.get(target_id)
            if not target:
                return TargetAttribution(
                    status="UNKNOWN",
                    confidence=0.0,
                    target_id=target_id,
                    evidence=[AttributionEvidence(type="NO_EVIDENCE", value="Target not found in repository")],
                    resolver_version=self.version
                )

            cand_hosts = [target["hostname"]] + target.get("aliases", [])
            cand_hosts_clean = [self.normalize_hostname(h) for h in cand_hosts if self.normalize_hostname(h)]
            configured_ips = target.get("metadata", {}).get("configured_ips", [])

            # a) Evaluate SNI if present
            if sni_clean:
                # Check exact SNI match
                for cand in cand_hosts_clean:
                    if sni_clean == cand:
                        return TargetAttribution(
                            status="ATTRIBUTED",
                            confidence=0.98,
                            target_id=target_id,
                            evidence=[AttributionEvidence(type="SNI_EXACT", value=sni_clean)],
                            resolver_version=self.version
                        )

                # Check subdomain SNI match
                for cand in cand_hosts_clean:
                    if self.is_subdomain_match(sni_clean, cand):
                        return TargetAttribution(
                            status="ATTRIBUTED",
                            confidence=0.90,
                            target_id=target_id,
                            evidence=[AttributionEvidence(type="SNI_SUBDOMAIN", value=sni_clean, detail=f"Subdomain match for {cand}")],
                            resolver_version=self.version
                        )

                # If SNI is present but does NOT match target host or aliases -> CONFLICTING_EVIDENCE / NOT_MATCHED
                return TargetAttribution(
                    status="NOT_MATCHED",
                    confidence=0.0,
                    target_id=target_id,
                    evidence=[AttributionEvidence(type="CONFLICTING_EVIDENCE", value=sni_clean, detail=f"SNI '{sni_clean}' does not match target '{target['hostname']}'")],
                    resolver_version=self.version
                )

            # b) Evaluate time-aware DNS correlation if SNI is missing
            if dst_ip:
                correlated_hosts = self.dns_cache.get_hostnames_for_ip(dst_ip)
                for corr_host in correlated_hosts:
                    for cand in cand_hosts_clean:
                        if self.is_subdomain_match(corr_host, cand):
                            return TargetAttribution(
                                status="PROBABLE",
                                confidence=0.75,
                                target_id=target_id,
                                evidence=[AttributionEvidence(type="DNS_MATCH", value=f"{corr_host} -> {dst_ip}")],
                                resolver_version=self.version
                            )

            # c) Evaluate configured destination IP evidence if present
            if dst_ip and dst_ip in configured_ips:
                return TargetAttribution(
                    status="PROBABLE",
                    confidence=0.40,
                    target_id=target_id,
                    evidence=[AttributionEvidence(type="DESTINATION_IP_MATCH", value=dst_ip)],
                    resolver_version=self.version
                )

            # d) No evidence found for target
            return TargetAttribution(
                status="UNKNOWN",
                confidence=0.0,
                target_id=target_id,
                evidence=[AttributionEvidence(type="NO_EVIDENCE", value="No observable SNI, DNS, or IP evidence for specified target")],
                resolver_version=self.version
            )

        # 2. Targetless Evaluation (General stream monitoring)
        if sni_clean:
            for tgt in target_repository.all(include_disabled=False):
                cand_hosts = [tgt["hostname"]] + tgt.get("aliases", [])
                for cand in cand_hosts:
                    cand_clean = self.normalize_hostname(cand)
                    if cand_clean:
                        if sni_clean == cand_clean:
                            return TargetAttribution(
                                status="ATTRIBUTED",
                                confidence=0.98,
                                target_id=tgt["target_id"],
                                evidence=[AttributionEvidence(type="SNI_EXACT", value=sni_clean)],
                                resolver_version=self.version
                            )
                        elif self.is_subdomain_match(sni_clean, cand_clean):
                            return TargetAttribution(
                                status="ATTRIBUTED",
                                confidence=0.90,
                                target_id=tgt["target_id"],
                                evidence=[AttributionEvidence(type="SNI_SUBDOMAIN", value=sni_clean)],
                                resolver_version=self.version
                            )

        # Fallback for targetless stream with no target match
        return TargetAttribution(
            status="UNKNOWN",
            confidence=0.0,
            target_id=None,
            evidence=[AttributionEvidence(type="NO_EVIDENCE", value="Targetless flow with no matching target")],
            resolver_version=self.version
        )

target_resolver = TargetResolver()
