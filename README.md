# SOC Investigation: Network Reconnaissance, SMB Password Guessing & Wazuh Detection

**Portfolio Project 2 | Defensive Security / SOC Analysis**  
**Investigation:** October 15–16, 2026  
**Environment:** Isolated VMware Workstation home lab  
**Tools:** Wazuh SIEM, Windows Security Event Logs, Sysmon, Wireshark, Nmap, Kali Linux, Windows 11

## Executive Summary

I investigated a controlled attack simulation involving TCP port reconnaissance and repeated SMB authentication failures against a Windows 11 endpoint. I correlated network observations with Windows Security events and Wazuh detections, reconstructed the authentication timeline, and checked for successful logons.

The simulation generated failed NTLM network logons and an account lockout for the local `testuser` account. I found no successful `testuser` logon in the Wazuh alerts or Windows Security logs examined.

**Outcome:** Detected password-guessing behavior and account lockout; no successful account compromise identified in the examined evidence. This conclusion is limited to the telemetry and time windows reviewed.

## Lab Architecture

| System | Address | Role |
|---|---|---|
| Kali Linux (`KALI-ATTACKER`) | `192.168.74.130` | Controlled attack simulator |
| Windows 11 (`WIN11-ENDPOINT`) | `192.168.74.129` | Target endpoint; Wazuh agent ID `002` |
| Ubuntu Server | `192.168.74.128` | Wazuh manager, indexer, and dashboard |

All testing occurred in a controlled virtual lab. The IP addresses are private lab addresses.

## Objectives

1. Observe network service discovery and identify exposed TCP services.
2. Generate and detect unsuccessful SMB authentication attempts.
3. Correlate Windows events and Wazuh alerts to reconstruct the attack timeline.
4. Determine whether the targeted account successfully authenticated.
5. Map observed behavior to MITRE ATT&CK and document an analyst disposition.

## Investigation Methodology and Evidence

### Phase 1 — TCP Reconnaissance

I conducted an Nmap TCP SYN scan from Kali against the Windows endpoint and analyzed the traffic using Wireshark.

| Nmap observation | Result |
|---|---|
| TCP 135 | Open (RPC) |
| TCP 139 | Open (NetBIOS Session Service) |
| TCP 445 | Open (SMB) |
| Other ports in the default 1,000-port scan | 997 filtered |

The filtered ports did not respond to the scan; this explains why I did not observe RST-ACK replies for those ports. This phase maps to **T1046 — Network Service Discovery**. Open ports alone do not establish exploitation or compromise.

**Evidence to add:** `screenshots/01-nmap-syn-scan.png`, `screenshots/02-wireshark-syn-probes.png`, `screenshots/03-wireshark-open-ports.png`.

### Phase 2 — SMB Authentication Simulation

Using an SMB client on Kali, I intentionally submitted incorrect credentials for the local Windows account `testuser`. The client reported `NT_STATUS_LOGON_FAILURE`; later attempts resulted in account lockout.

Windows Security Event **4625** showed:

| Field | Observed value | Meaning |
|---|---|---|
| Source IP | `192.168.74.130` | Kali lab host |
| Destination endpoint | `192.168.74.129` | Windows lab host |
| Target username | `testuser` | Account under test |
| Logon type | `3` | Network logon |
| Authentication package | `NTLM` | Windows authentication mechanism |
| Logon process | `NtLmSsp` | NTLM security support provider |
| Status | `0xC000006D` | Logon failure |
| Substatus | `0xC000006A` | Incorrect password |

The network logon type and NTLM fields are consistent with the SMB test; the prior port-445 capture provides supporting network context. The observed behavior maps to **T1110.001 — Password Guessing**, not password spraying: the reviewed events targeted one account.

**Evidence to add:** `screenshots/04-smb-authentication-attempts.png`, `screenshots/05-windows-event-4625.png`.

### Phase 3 — Wazuh Correlation and Account Lockout

The investigation identified the following Wazuh rules:

| Wazuh rule | Detection |
|---|---|
| `60122` | Logon failure — unknown user or bad password |
| `60204` | Multiple Windows logon failures |
| `60115` | User account locked out |

The reviewed search results included **10 individual failed-logon alerts and one correlation alert**. The correlation alert is not an additional independent password attempt; alert count must not be confused with the number of authentication attempts.

Windows Security Event **4740** confirmed that `testuser` was locked. Its event message identified `KALI-ATTACKER` as the caller computer. The subject was the local SYSTEM context (`WIN11-ENDPOINT$`, SID `S-1-5-18`), which is not evidence that the machine account was compromised.

#### Reconstructed Timeline

Times below use the Wazuh dashboard's displayed local time on **October 15, 2026**.

| Time | Observed event |
|---|---|
| 16:39:53 | First observed failed authentication in reviewed results |
| 16:52:34 | Wazuh multiple-logon-failures correlation alert |
| 16:53:09 | Last observed failed-login activity / account lockout period |
| 16:53:09.390 | Wazuh timestamp for account-lockout alert (Event 4740) |

The interval between the first and last observed authentication activity was approximately **13 minutes, 16 seconds**. This does not imply uninterrupted attempts throughout the interval. The Windows event's UTC system time may differ slightly from the Wazuh ingestion/display timestamp.

**Evidence to add:** `screenshots/06-wazuh-multiple-logon-failures.png`, `screenshots/07-windows-account-lockout-4740.png`, `screenshots/08-wazuh-authentication-timeline.png`.

### Phase 4 — Check for Successful Authentication

I searched Wazuh for Event **4624** associated with `testuser`, then examined Windows Security logs directly in Event Viewer. No successful logon for that account was found in the examined records.

I also inspected a separate Event 4624 with **Logon Type 5**, `NT AUTHORITY\SYSTEM`, and `services.exe`. This was consistent with a Windows service logon, **not** evidence of an SMB login by `testuser`.

**Assessment:** No successful account access was identified in the available evidence. Absence of matching events is not absolute proof that no authentication succeeded outside the collection scope or reviewed time range.

**Evidence to add later:** `screenshots/09-successful-logon-search.png` (only if a suitable original screenshot is captured).

### Additional Alert Triage

During the investigation, Wazuh also flagged account-discovery commands involving `net.exe` and `net1.exe`. I correlated Sysmon process GUIDs and traced their execution to `wazuh-agent.exe`, running under the local SYSTEM context. I assessed these alerts as **likely benign security-monitoring activity**, rather than evidence of attacker execution. The specific Wazuh module responsible was not independently verified.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence and interpretation |
|---|---|---|
| Network Service Discovery | T1046 | Controlled Nmap SYN scan and Wireshark observations |
| Password Guessing | T1110.001 | Repeated failed NTLM logons targeting `testuser` |

Wazuh also mapped the lockout to **T1531 — Account Access Removal**. In this lab, the lockout was a defensive consequence of repeated failures, **not** evidence of an attacker intentionally removing account access.

## Incident Assessment

**Illustrative severity: Medium.** The activity involved repeated password guessing and a confirmed account lockout, without identified successful access. A production SOC would apply its own severity matrix and consider privileged-account exposure, asset criticality, operational impact, and breadth of targeting.

**Observed impact:** `testuser` was locked out. No confirmed lateral movement, attacker-controlled process execution, or data exfiltration was found in the reviewed evidence. This is not a claim that every possible telemetry source was exhaustively examined.

## Recommended Defensive Actions

- Review authentication attempts from the source and check for additional targeted accounts or hosts.
- Monitor Event IDs 4625, 4624, and 4740 together, rather than treating each event in isolation.
- Use account lockout protections and multifactor authentication where applicable.
- Restrict SMB exposure to trusted network segments and hosts.
- Restore locked account access only after appropriate verification and follow organizational incident-response procedures.

## Skills Demonstrated

- **SIEM triage:** Wazuh Threat Hunting queries, rule interpretation, alert correlation.
- **Windows authentication:** 4625/4624/4740, NTLM, logon types, failure status codes.
- **Network analysis:** TCP SYN scan interpretation, SMB exposure, Wireshark traffic review.
- **Endpoint investigation:** Sysmon Event 1 and parent-child process correlation during secondary alert triage.
- **Analyst judgment:** Severity assessment, benign-event recognition, evidence limitations, ATT&CK mapping.

## Lessons Learned

1. A correlated SIEM alert does not necessarily represent a separate underlying event.
2. A successful Windows service logon is not equivalent to successful remote authentication.
3. A suspicious-looking command may be benign; its process ancestry and execution context matter.
4. A defensible incident conclusion must distinguish observed facts, likely explanations, and unverified assumptions.

## Evidence and Reproducibility

Screenshot filenames mentioned above are **planned evidence filenames**; the image files must be uploaded separately before linking them in this README. No screenshots have been fabricated for this report. Redact sensitive information before publishing; these private lab IP addresses and the test username are included for reproducibility.

## Final Conclusion

This investigation demonstrated a practical SOC workflow from network reconnaissance through authentication monitoring, SIEM correlation, account-lockout analysis, and successful-logon checks. The simulated SMB password-guessing activity was detected, and the available evidence did not show successful account compromise. The project highlights evidence-based incident triage and the importance of distinguishing observed findings from assumptions.
