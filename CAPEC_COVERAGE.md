# CAPEC Coverage Attestation

- **Skill used:** capec-security-hardening
- **CAPEC version:** 3.9
- **Latest MITRE version:** 3.9 (as of 2026-07-07)
- **Project type(s):** graphql, web-api, network-service
- **Core patterns tested this round:** 1 (CAPEC-274: HTTP Verb Tampering)
- **Total core patterns:** 143 identified, 1 completed
- **Tangential patterns reviewed:** 0
- **Not applicable (excluded):** 263 patterns (hardware, cellular, physical, social engineering, mobile, GPS, Bluetooth)

## Round 1: R5 — Protocol & Communication

| CAPEC-ID | Name | Status | Test File |
|---|---|---|---|
| CAPEC-274 | HTTP Verb Tampering | ✅ | internal/proxy/capec_round_r5_verb_tamper_test.go |

## Pattern-by-pattern breakdown

| CAPEC-ID | Name | Mechanism | Round | Status | Test File |
|---|---|---|---|---|---|
| CAPEC-274 | HTTP Verb Tampering | Protocol & Communication | R5 | ✅ | internal/proxy/capec_round_r5_verb_tamper_test.go |

## Excluded by project type

| Mechanism | Reason |
|---|---|
| Hardware attacks (CAPEC-390..682) | No hardware/firmware component |
| Cellular/WiFi/Bluetooth | Not a mobile/cellular project |
| Social Engineering (CAPEC-410..435) | Not a user-facing application |
| Physical Security (CAPEC-390..402) | No physical access surface |
| Supply Chain (CAPEC-438..548) | Out of scope for proxy sidecar |
| GPS/Jamming/Orbital | Not applicable to HTTP proxy |
