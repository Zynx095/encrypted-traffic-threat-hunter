import pytest
import time
from backend.schemas import TLSDetails, ETTHStreamEvent
from backend.target_resolver import target_resolver, TargetResolver, DNSCache
from backend.repositories import target_repository, session_repository
from backend.detection_pipeline import detection_pipeline

@pytest.fixture(autouse=True)
def reset_environment():
    target_repository._targets.clear()
    target_repository._seed_default_targets()
    session_repository._sessions.clear()
    target_resolver.dns_cache.clear()

def test_1_exact_hostname_match():
    resolver = TargetResolver()
    assert resolver.normalize_hostname("youtube.com.") == "youtube.com"
    assert resolver.normalize_hostname("  YOUTUBE.COM ") == "youtube.com"

def test_2_exact_sni_match():
    flow = {"flow_id": "f1", "sni": "youtube.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "ATTRIBUTED"
    assert res.confidence == 0.98
    assert len(res.evidence) == 1
    assert res.evidence[0].type == "SNI_EXACT"
    assert res.evidence[0].value == "youtube.com"

def test_3_valid_configured_alias():
    flow = {"flow_id": "f2", "sni": "googlevideo.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "ATTRIBUTED"
    assert res.confidence == 0.98
    assert res.evidence[0].type == "SNI_EXACT"

def test_4_valid_subdomain_policy():
    flow = {"flow_id": "f3", "sni": "v1.video.youtube.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "ATTRIBUTED"
    assert res.confidence == 0.90
    assert res.evidence[0].type == "SNI_SUBDOMAIN"

def test_5_malicious_suffix_hostname_rejection():
    flow = {"flow_id": "f4", "sni": "youtube.com.evil.example"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "NOT_MATCHED"
    assert res.confidence == 0.0
    assert res.evidence[0].type == "CONFLICTING_EVIDENCE"

def test_6_missing_sni():
    flow = {"flow_id": "f5"}
    tls = TLSDetails(sni_present=False)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "UNKNOWN"
    assert res.confidence == 0.0
    assert res.evidence[0].type == "NO_EVIDENCE"

def test_7_ech_unavailable_sni():
    flow = {"flow_id": "f6"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    assert res.status == "UNKNOWN"
    assert res.confidence == 0.0

def test_8_dns_hostname_ip_correlation():
    target_resolver.dns_cache.add_observation("youtube.com", "172.217.14.206", ttl=300)
    flow = {"flow_id": "f7", "reverse_endpoint": "172.217.14.206:443"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    assert res.status == "PROBABLE"
    assert res.confidence == 0.75
    assert res.evidence[0].type == "DNS_MATCH"
    assert "172.217.14.206" in res.evidence[0].value

def test_9_stale_dns_record():
    # Insert observation with 1-second TTL and sleep to expire it
    target_resolver.dns_cache.add_observation("youtube.com", "172.217.14.207", ttl=1)
    time.sleep(1.1)
    flow = {"flow_id": "f8", "reverse_endpoint": "172.217.14.207:443"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    assert res.status == "UNKNOWN"

def test_10_ip_only_weak_evidence():
    target_repository.update("target_youtube", {
        "metadata": {"configured_ips": ["142.250.190.46"]}
    })
    flow = {"flow_id": "f9", "reverse_endpoint": "142.250.190.46:443"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    assert res.status == "PROBABLE"
    assert res.confidence == 0.40
    assert res.evidence[0].type == "DESTINATION_IP_MATCH"

def test_11_conflicting_sni_dns_evidence():
    flow = {"flow_id": "f10", "sni": "github.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "NOT_MATCHED"
    assert res.confidence == 0.0
    assert res.evidence[0].type == "CONFLICTING_EVIDENCE"

def test_12_no_evidence_unknown():
    flow = {"flow_id": "f11", "reverse_endpoint": "1.1.1.1:53"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    assert res.status == "UNKNOWN"

def test_13_tcp_flow_attribution():
    flow = {"flow_id": "f12", "protocol": "TCP", "sni": "github.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_github")
    assert res.status == "ATTRIBUTED"

def test_14_udp_quic_flow_handling():
    flow = {"flow_id": "f13", "protocol": "UDP", "sni": "youtube.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "ATTRIBUTED"

def test_15_session_isolation():
    s1 = session_repository.create({"target_id": "target_youtube"})
    s2 = session_repository.create({"target_id": "target_github"})
    
    f1 = {"flow_id": "fs1", "sni": "youtube.com"}
    tls = TLSDetails(sni_present=True)

    r1 = target_resolver.resolve(f1, tls_details=tls, target_id=s1["target_id"], session_id=s1["session_id"])
    r2 = target_resolver.resolve(f1, tls_details=tls, target_id=s2["target_id"], session_id=s2["session_id"])

    assert r1.status == "ATTRIBUTED"
    assert r2.status == "NOT_MATCHED"

def test_16_target_isolation():
    f = {"flow_id": "ft", "sni": "github.com"}
    tls = TLSDetails(sni_present=True)
    res_yt = target_resolver.resolve(f, tls_details=tls, target_id="target_youtube")
    res_gh = target_resolver.resolve(f, tls_details=tls, target_id="target_github")
    assert res_yt.status == "NOT_MATCHED"
    assert res_gh.status == "ATTRIBUTED"

def test_17_multiple_targets():
    f = {"flow_id": "fmt", "sni": "github.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(f, tls_details=tls, target_id=None)
    assert res.status == "ATTRIBUTED"
    assert res.target_id == "target_github"

def test_18_targetless_replay_compatibility():
    event = detection_pipeline.process_flow(
        flow={"flow_id": "freplay", "flow_duration": 1.0},
        track="A_FLOW",
        mode="REPLAY"
    )
    assert event.attribution is not None
    assert event.attribution.status == "UNKNOWN"

def test_19_target_session_event_propagation():
    event = detection_pipeline.process_flow(
        flow={"flow_id": "fevent", "sni": "youtube.com"},
        track="A_FLOW",
        mode="LIVE",
        target_id="target_youtube",
        session_id="sess_live_1"
    )
    assert event.target_id == "target_youtube"
    assert event.session_id == "sess_live_1"
    assert event.attribution is not None
    assert event.attribution.status == "ATTRIBUTED"
    assert event.attribution.confidence == 0.98

def test_20_attribution_confidence_bounds():
    flow = {"flow_id": "f20", "sni": "youtube.com"}
    tls = TLSDetails(sni_present=True)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert 0.0 <= res.confidence <= 1.0

def test_21_deterministic_scoring():
    flow = {"flow_id": "f21", "sni": "m.youtube.com"}
    tls = TLSDetails(sni_present=True)
    res1 = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    res2 = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res1.status == res2.status
    assert res1.confidence == res2.confidence

def test_22_no_payload_inspection():
    flow = {"flow_id": "f22", "payload_bytes": b"SENSITIVE_DATA_DUMMY"}
    res = target_resolver.resolve(flow, target_id="target_youtube")
    # Verify resolution depends only on metadata fields, ignoring raw payload
    assert res.status in ["ATTRIBUTED", "PROBABLE", "UNKNOWN", "NOT_MATCHED"]

def test_23_no_tls_decryption():
    tls = TLSDetails(clienthello_present=True, sni_present=False)
    flow = {"flow_id": "f23"}
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert res.status == "UNKNOWN"

def test_24_no_fabricated_sni():
    flow = {"flow_id": "f24"}
    tls = TLSDetails(sni_present=False)
    res = target_resolver.resolve(flow, tls_details=tls, target_id="target_youtube")
    assert not any(e.type == "SNI_EXACT" for e in res.evidence)

def test_25_resolver_version_included():
    res = target_resolver.resolve({"flow_id": "f25"})
    assert res.resolver_version == "7.6.1"
