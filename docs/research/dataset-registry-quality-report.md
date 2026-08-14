# Dataset Registry Quality Report

**Date:** 2026-08-15
**Purpose:** Document the quality and consistency of the ETTH dataset registry
**Scope:** This report documents the schema validation, consistency checks, and unresolved verification items.

## 1. Registry Coverage

- Total rows in CSV: 6 (including header)
- Data rows (datasets): 5
- Expected datasets: 5 (DS-001 through DS-005)
  - **PASS**: Dataset count matches expected

## 2. Schema Validation

- Header has 38 columns as expected

## 3. Consistency Checks

- No duplicate dataset IDs found
- No duplicate dataset names found

### Required Fields Completeness
- All dataset IDs and names are present
- All evidence_source fields are present

- All verification_status values are allowed
- All suitability values are allowed

- All planned_role values are allowed

- All evidence_source fields are non-empty

## 4. Unresolved Verification Items

The following fields have NOT_VERIFIED or PENDING values across the registry:

- **bidirectional_pcap**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **clienthello_available**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **serverhello_available**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **ja3_available**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **ja3_computable**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **ja3s_computable**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **ja4_available**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **ja4_computable**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **download_status**: 4 dataset(s) with NOT_VERIFIED or PENDING
- **c2_traffic**: 3 dataset(s) with NOT_VERIFIED or PENDING
- **class_balance**: 3 dataset(s) with NOT_VERIFIED or PENDING
- **raw_pcap**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **flow_features_available**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **packet_lengths_available**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **iat_available**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **benign_traffic**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **malware_traffic**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **label_quality**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **capture_environment**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **temporal_information**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **dataset_size**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **verification_status**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **planned_role**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **known_leakage**: 2 dataset(s) with NOT_VERIFIED or PENDING
- **known_limitations**: 1 dataset(s) with NOT_VERIFIED or PENDING
- **license_or_access**: 1 dataset(s) with NOT_VERIFIED or PENDING
- **suitability**: 1 dataset(s) with NOT_VERIFIED or PENDING
- **evidence_source**: 1 dataset(s) with NOT_VERIFIED or PENDING
- **notes**: 1 dataset(s) with NOT_VERIFIED or PENDING

## 5. Contradictions Found

- No logical contradictions detected in the data (e.g., no field marked both VERIFIED_YES and VERIFIED_NO)

## 6. Research Integrity Statement

This report:
- Documents the current state of the dataset registry without altering any data.
- Uses only the evidence present in the registry and associated documents.
- Does not invent verification results or convert uncertainty into positive claims.
- Clearly distinguishes between VERIFIED, PARTIALLY_VERIFIED, NOT_VERIFIED, and PENDING states.
- Is intended for transparency and reproducibility.