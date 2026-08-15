<div align="center">

# Encrypted Traffic Threat Hunter (ETTH)

### Academic Research Project — Encrypted Traffic Analysis & Threat Hunting

[![Research Status](https://img.shields.io/badge/Research-Active-success?style=for-the-badge)](#-research-status)
[![Current Phase](https://img.shields.io/badge/Phase-6%20%7C%20Data%20Pipeline-orange?style=for-the-badge)](#-phase-progress)
[![Focus](https://img.shields.io/badge/Focus-TLS%20%7C%20JA3%20%7C%20JA4%20%7C%20Flow%20Analysis-blue?style=for-the-badge)](#-research-objective)
[![Data Safety](https://img.shields.io/badge/Data%20Safety-Leakage%20Controlled-red?style=for-the-badge)](#-data-safety)
[![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

**Investigating whether TLS fingerprint features and encrypted-flow behavioral features can be combined to improve malicious encrypted-traffic detection without decrypting network payloads.**

</div>

---

## Table of Contents

- [Research Objective](#-research-objective)
- [Research Status](#-research-status)
- [Dataset Strategy](#-dataset-strategy)
- [Pipeline Architecture](#-pipeline-architecture)
- [Phase Progress](#-phase-progress)
- [Experimental Design](#-experimental-design)
- [Repository Structure](#-repository-structure)
- [Data Safety](#-data-safety)
- [Research Methodology](#-research-methodology)
- [Current Technical Decisions](#-current-technical-decisions)
- [Future Roadmap](#-future-roadmap)
- [Research Principles](#-research-principles)
- [Project Status](#-project-status)

---

## Research Objective

The **Encrypted Traffic Threat Hunter (ETTH)** project investigates whether encrypted network traffic can be classified for malicious behavior using observable network metadata rather than decrypting application payloads.

The central research question is:

> **Does combining TLS fingerprint information with encrypted-flow behavioral characteristics provide a measurable advantage for malicious encrypted-traffic detection compared with using either feature family independently?**

The project focuses on modern encrypted traffic, particularly TLS-based communication, and investigates the combination of:

- **JA3** — Client TLS fingerprint
- **JA3S** — Server TLS fingerprint
- **JA4** — Modern TLS client fingerprint
- **Flow-level behavioral features**
- Packet-length sequences
- Inter-arrival times
- Bidirectional packet/byte statistics
- TLS structural metadata
- SNI presence
- ALPN information

The system is designed around **metadata-level analysis**.

### No Payload Decryption

ETTH does **not** decrypt TLS application payloads.

The research operates on information observable from encrypted network traffic, including:

```text
TLS Handshake Metadata
        +
TLS Fingerprints
        +
Packet / Flow Behavior
        +
Temporal Characteristics
        ↓
Leakage-Controlled Features
        ↓
Threat Classification