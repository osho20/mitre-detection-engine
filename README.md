\# Mini Detection Engine



A Python tool that parses Windows Event Logs (.evtx) and detects real attack techniques mapped to MITRE ATT\&CK.



\## Techniques Detected

\- \*\*T1098\*\* - Account Manipulation (DSRM Password Change) - Event ID 4794

\- \*\*T1003.006\*\* - OS Credential Dumping (DCSync ACL Modification) - Event ID 5136



\## Data Source

Sample logs from real attack simulations: \[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)



\## How it works

Parses .evtx files, scans each record for known malicious Event ID signatures, and prints an alert with the corresponding MITRE ATT\&CK technique when a match is found.



\## Usage

```

python detect.py

```

