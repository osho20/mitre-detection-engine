# Mini Detection Engine

A Python tool that parses Windows Event Logs (.evtx) and detects real attack techniques mapped to MITRE ATT&CK, validated against real-world attack log samples.

## Techniques Detected

| MITRE ATT&CK ID | Technique | Tactic | Event ID |
|---|---|---|---|
| T1098 | Account Manipulation (DSRM Password Change) | Persistence | 4794 |
| T1003.006 | OS Credential Dumping (DCSync) | Credential Access | 5136 |
| T1021.001 | Remote Services (RDP Lateral Movement) | Lateral Movement | 104 |
| T1553.006 | Subvert Trust Controls (Code Signing) | Defense Evasion | 4826 |
| T1018 | Remote System Discovery (Named Pipes) | Discovery | 18 |
| T1218 | System Binary Proxy Execution (LOLBAS) | Defense Evasion | 7 |

## How It Works
The tool parses `.evtx` files, scans each log record for known malicious Event ID signatures (and supporting context like process names), and prints an alert mapped to the corresponding MITRE ATT&CK technique when a match is found.

## Data Source
Real attack simulation logs from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

## Usage