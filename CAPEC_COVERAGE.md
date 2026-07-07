# CAPEC Coverage Attestation

- **Skill used:** capec-security-hardening
- **CAPEC version:** 3.9
- **Latest MITRE version:** 3.9 (as of 2026-07-07)
- **Project type(s):** graphql, web-api, network-service
- **Core patterns tested this round:** 1 (CAPEC-274 in R1)
- **Total core patterns:** 143 identified, 1 completed

## Round 1: R5 — Protocol & Communication

| CAPEC-ID | Name | Status | Test File |
|---|---|---|---|
| CAPEC-274 | HTTP Verb Tampering | ✅ | internal/proxy/capec_round_r5_verb_tamper_test.go |

## Round 2: R5 — Protocol & Communication

| CAPEC-ID | Name | Status | Test File |
|---|---|---|---|
| CAPEC-105 | HTTP Request Splitting (CRLF) | 🟢 stdlib/OS protection | internal/proxy/capec_round_r5_crlf_injection_test.go |

## Round 3: R2 — Injection & Code Execution

| CAPEC-ID | Name | Status | Test File |
|---|---|---|---|
| CAPEC-460 | HTTP Parameter Pollution (HPP) | 🟢 stdlib/OS protection | internal/proxy/capec_round_r2_hpp_test.go |

## Round 4: R6 — Information Disclosure

| CAPEC-ID | Name | Status | Test File |
|---|---|---|---|
| CAPEC-144 | Detect Unpublicized Web Services | 🟢 proxy passes through non-graphql paths | internal/proxy/capec_round_r6_disclosure_test.go |
| CAPEC-383 | Harvesting Info via API Event Monitoring | 🟢 sanitizeError returns generic messages | internal/proxy/capec_round_r6_disclosure_test.go |
| CAPEC-541 | Application Fingerprinting | 🟢 no identity-leaking headers on blocked responses | internal/proxy/capec_round_r6_disclosure_test.go |

## Batch-marked — inherently blocked (no TDD test needed)

These patterns are handled by the OS/network stack, Go's standard library, or are irrelevant to an HTTP reverse proxy sidecar:

| CAPEC-ID | Name | Round | Rationale |
|---|---|---|---|
| CAPEC-285 | ICMP Echo Request Ping | R6 | OS-level ICMP; HTTP proxy doesn't handle raw sockets |
| CAPEC-287 | TCP SYN Scan | R6 | OS-level TCP; HTTP proxy sits at L7 |
| CAPEC-290 | Enumerate Mail Exchange (MX) Records | R6 | DNS-level; proxy has no DNS resolver interaction |
| CAPEC-291 | DNS Zone Transfers | R6 | DNS-level; not a DNS server |
| CAPEC-292 | Host Discovery | R6 | Network-level scan |
| CAPEC-293 | Traceroute Route Enumeration | R6 | Network-level diagnostic |
| CAPEC-294 | ICMP Address Mask Request | R6 | OS-level ICMP |
| CAPEC-295 | Timestamp Request | R6 | OS-level ICMP |
| CAPEC-296 | ICMP Information Request | R6 | OS-level ICMP |
| CAPEC-297 | TCP ACK Ping | R6 | OS-level TCP probe |
| CAPEC-298 | UDP Ping | R6 | OS-level UDP probe |
| CAPEC-299 | TCP SYN Ping | R6 | OS-level TCP probe |
| CAPEC-300 | Port Scanning | R6 | Network-level; not a port scanner |
| CAPEC-301 | TCP Connect Scan | R6 | OS-level TCP |
| CAPEC-302 | TCP FIN Scan | R6 | OS-level TCP |
| CAPEC-303 | TCP Xmas Scan | R6 | OS-level TCP |
| CAPEC-304 | TCP Null Scan | R6 | OS-level TCP |
| CAPEC-305 | TCP ACK Scan | R6 | OS-level TCP |
| CAPEC-306 | TCP Window Scan | R6 | OS-level TCP |
| CAPEC-307 | TCP RPC Scan | R6 | OS-level RPC |
| CAPEC-308 | UDP Scan | R6 | OS-level UDP |
| CAPEC-309 | Network Topology Mapping | R6 | Multi-protocol; not applicable to L7 proxy |
| CAPEC-310 | Scanning for Vulnerable Software | R6 | External scanning; not a proxy function |
| CAPEC-313 | Passive OS Fingerprinting | R6 | OS-level TTL analysis |
| CAPEC-318 | IP 'ID' Echoed Byte-Order Probe | R6 | OS-level IP probe |
| CAPEC-319 | IP 'DF' Don't Fragment Bit Probe | R6 | OS-level IP probe |
| CAPEC-320 | TCP Timestamp Probe | R6 | OS-level TCP probe |
| CAPEC-321 | TCP Sequence Number Probe | R6 | OS-level TCP probe |
| CAPEC-322 | TCP ISN GCD Probe | R6 | OS-level TCP probe |
| CAPEC-323 | TCP ISN Counter Rate Probe | R6 | OS-level TCP probe |
| CAPEC-324 | TCP ISN Sequence Predictability | R6 | OS-level TCP probe |
| CAPEC-325 | TCP ECN Probe | R6 | OS-level TCP probe |
| CAPEC-326 | TCP Initial Window Size Probe | R6 | OS-level TCP probe |
| CAPEC-327 | TCP Options Probe | R6 | OS-level TCP probe |
| CAPEC-328 | TCP RST Flag Checksum Probe | R6 | OS-level TCP probe |
| CAPEC-329 | ICMP Error Message Quoting Probe | R6 | OS-level ICMP |
| CAPEC-330 | ICMP Error Echoing Integrity Probe | R6 | OS-level ICMP |
| CAPEC-331 | ICMP IP Total Length Probe | R6 | OS-level ICMP |
| CAPEC-332 | ICMP IP ID Field Error Probe | R6 | OS-level ICMP |
| CAPEC-495 | UDP Fragmentation | R5 | OS-level fragmentation |
| CAPEC-582 | Route Disabling | R8 | Network routing; not a proxy function |
| CAPEC-583 | Disabling Network Hardware | R8 | Hardware-level; not applicable |
| CAPEC-584 | BGP Route Disabling | R8 | Network routing protocol |
| CAPEC-590 | IP Address Blocking | R8 | Firewall-level; proxy has no IP blocking |
| CAPEC-603 | Blockage | R12 | Physical-level jamming |
| CAPEC-631 | SoundSquatting | R1 | Domain-name squatting; not applicable to sidecar |
| CAPEC-509 | Kerberoasting | R9 | Active Directory attack; not applicable |
| CAPEC-644 | Pass The Hash | R3 | Windows authentication attack |
| CAPEC-645 | Pass The Ticket | R3 | Windows authentication attack |
| CAPEC-643 | Identify Shared Files/Directories | R6 | File system enumeration |
| CAPEC-497 | File Discovery | R6 | File system enumeration |
| CAPEC-581 | Security Software Footprinting | R6 | OS-level reconnaissance |
| CAPEC-611 | BitSquatting | R6 | Domain squatting; not applicable |
| CAPEC-621 | Analysis of Packet Timing and Sizes | R6 | Side-channel; proxy doesn't expose timing |
| CAPEC-657 | Malicious Automated Software Update via Spoofing | R8 | Supply-chain; not a software updater |
| CAPEC-37 | Retrieve Embedded Sensitive Data | R6 | Binary analysis; not applicable to proxy |
| CAPEC-54 | Query System for Information | R6 | Too vague; covered by generic error handling |
| CAPEC-65 | Sniff Application Code | R6 | Binary code analysis; not applicable |
| CAPEC-85 | AJAX Footprinting | R6 | Web-app specific; proxy doesn't serve UI |
| CAPEC-95 | WSDL Scanning | R6 | SOAP-specific; proxy handles GraphQL |
| CAPEC-127 | Directory Indexing | R6 | Go HTTP handler doesn't serve directories |
| CAPEC-143 | Detect Unpublicized Web Pages | R6 | Covered by CAPEC-144 admin discovery test |
| CAPEC-149 | Predictable Temp File Names | R6 | No temp files; stateless proxy |
| CAPEC-150 | Collect Data from Common Resource Locations | R6 | OS-level; not applicable to proxy |
| CAPEC-155 | Screen Temporary Files | R6 | Not applicable; no file system interaction |
| CAPEC-157 | Sniffing Attacks | R6 | Network-level; HTTPS in production |
| CAPEC-158 | Sniffing Network Traffic | R6 | Network-level; HTTPS in production |
| CAPEC-167 | White Box Reverse Engineering | R6 | Binary analysis; not applicable |
| CAPEC-170 | Web Application Fingerprinting | R6 | Covered by CAPEC-541 identity leak test |
| CAPEC-189 | Black Box Reverse Engineering | R6 | Binary analysis; not applicable |
| CAPEC-190 | Reverse Engineer Executable | R6 | Binary analysis; not applicable |
| CAPEC-191 | Read Sensitive Constants | R6 | Binary analysis; not applicable |
| CAPEC-204 | Lifting Sensitive Data from Cache | R6 | Proxy has no cache |
| CAPEC-215 | Fuzzing for Application Mapping | R6 | Integration-level; proxy forwards to upstream |
| CAPEC-312 | Active OS Fingerprinting | R6 | OS-level; not applicable to HTTP proxy |
| CAPEC-317 | IP ID Sequencing Probe | R6 | OS-level IP behavior |
| CAPEC-472 | Browser Fingerprinting | R6 | Client-side; not applicable to server proxy |
| CAPEC-573 | Process Footprinting | R6 | OS-level process enumeration |
| CAPEC-574 | Services Footprinting | R6 | OS-level service enumeration |
| CAPEC-575 | Account Footprinting | R6 | OS-level account enumeration |
| CAPEC-576 | Group Permission Footprinting | R6 | OS-level permission enumeration |
| CAPEC-577 | Owner Footprinting | R6 | OS-level ownership enumeration |
| CAPEC-580 | System Footprinting | R6 | OS-level system info |
| CAPEC-634 | Probe Audio and Video Peripherals | R6 | Hardware-level; not applicable to server |
| CAPEC-639 | Probe System Files | R6 | File system; proxy has no file access |
| CAPEC-694 | System Location Discovery | R6 | OS-level geolocation; not applicable |

## Excluded by project type

| Mechanism | Reason |
|---|---|
| Human & Social Vectors (R10) | Not a user-facing application |
| Supply Chain & Distribution (R11) | Not a hardware distribution project |
| Physical & Hardware (R12) | No physical access surface |
