# UC-ENDPOINT-001 Possible LSASS Credential Dump

## Alert name

Possible LSASS credential dump from suspicious process access or known dumping tool.

## Objective

Detect activity consistent with credential dumping from LSASS memory using Mimikatz, ProcDump, comsvcs.dll, task manager dump behaviour, or suspicious process access patterns. The use case supports rapid containment of endpoint credential theft.

## Threat scenario

An attacker gains code execution on a Windows endpoint and attempts to extract credentials from LSASS memory. Stolen credentials may be used for privilege escalation, lateral movement, persistence, or cloud account compromise.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| MDE DeviceProcessEvents | Detect known tools and suspicious command lines | Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256 |
| MDE DeviceEvents | Detect LSASS access events where available | Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessFileName, InitiatingProcessCommandLine |
| MDE DeviceAlertEvents | Correlate Defender alerts | Timestamp, DeviceName, AlertTitle, Severity, Category |
| Identity and network logs | Identify follow-on compromise | Account use, remote connections, privileged sign-ins |

## Detection logic

### Microsoft Sentinel KQL

```kql
let lookback = 1d;
let dumpTools = dynamic(["mimikatz.exe", "procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe", "sqldumper.exe", "nanodump.exe", "dumpert.exe"]);
let suspiciousTerms = dynamic(["sekurlsa", "lsass", "comsvcs.dll", "MiniDump", "-ma", "--write", "nanodump", "dumpert"]);
let toolSignals = DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (dumpTools) or ProcessCommandLine has_any (suspiciousTerms)
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "comsvcs.dll", "MiniDump", "-ma")
| project AlertTime=Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, ReportId;
let lsassAccess = DeviceEvents
| where Timestamp >= ago(lookback)
| where ActionType has_any ("Lsass", "ProcessAccess", "CredentialDumping") or tostring(AdditionalFields) has_any ("lsass.exe", "PROCESS_VM_READ", "0x0010")
| where tostring(AdditionalFields) has_any ("lsass.exe", "PROCESS_VM_READ", "0x0010")
| project AlertTime=Timestamp, DeviceName, InitiatingProcessAccountName, FileName=InitiatingProcessFileName, ProcessCommandLine=InitiatingProcessCommandLine, AdditionalFields, ReportId;
union toolSignals, lsassAccess
| summarize FirstSeen=min(AlertTime), LastSeen=max(AlertTime), Evidence=make_set(pack("FileName", FileName, "CommandLine", ProcessCommandLine, "AdditionalFields", tostring(AdditionalFields)), 10) by DeviceName, InitiatingProcessAccountName
| project AlertTime=LastSeen, DeviceName, InitiatingProcessAccountName, FirstSeen, LastSeen, Evidence
```

### Defender Advanced Hunting query

```kql
let lookback = 1d;
let dumpTools = dynamic(["mimikatz.exe", "procdump.exe", "procdump64.exe", "nanodump.exe", "dumpert.exe", "rundll32.exe"]);
DeviceProcessEvents
| where Timestamp >= ago(lookback)
| where FileName in~ (dumpTools)
   or ProcessCommandLine has_any ("sekurlsa", "lsass", "comsvcs.dll", "MiniDump", "-ma", "nanodump", "dumpert")
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "comsvcs.dll", "MiniDump", "-ma")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, ReportId
| union (
    DeviceEvents
    | where Timestamp >= ago(lookback)
    | where tostring(AdditionalFields) has_any ("lsass.exe", "PROCESS_VM_READ", "0x0010")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName=InitiatingProcessFileName, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256="", ReportId
)
| order by Timestamp desc
```

### Sigma rule

```yaml
title: Suspicious LSASS Process Access For Credential Dumping
id: 05b08f18-8f7a-4d35-9484-0ec4d0105ebf
status: experimental
description: Detects suspicious process access to LSASS or known credential dumping command lines.
author: SOC Use Cases and Playbooks
logsource:
  product: windows
  category: process_access
detection:
  selection_lsass_access:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x10'
      - '0x1010'
      - '0x1410'
      - '0x143a'
  selection_tools:
    SourceImage|endswith:
      - '\\mimikatz.exe'
      - '\\procdump.exe'
      - '\\procdump64.exe'
      - '\\nanodump.exe'
      - '\\dumpert.exe'
  filter_legitimate:
    SourceImage|contains:
      - '\\Windows Defender\\'
      - '\\Microsoft Defender\\'
      - '\\Windows Error Reporting\\'
  condition: (selection_lsass_access or selection_tools) and not filter_legitimate
fields:
  - UtcTime
  - Computer
  - SourceImage
  - TargetImage
  - GrantedAccess
  - CallTrace
falsepositives:
  - Legitimate AV or EDR inspection.
  - Windows Error Reporting.
  - Authorised penetration test tooling.
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
```

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | The detection identifies suspicious LSASS memory access or known dumping tool execution. |

## Severity

Critical.

Treat as an active incident unless confirmed as authorised security testing or a known benign security tool.

## False positive scenarios

- Legitimate AV, EDR, or forensic tools accessing LSASS for inspection.
- Windows Error Reporting or crash dump generation.
- Authorised penetration test or red-team exercise.
- Administrative troubleshooting that uses ProcDump under an approved change.

## Tuning notes

- Maintain allowlists for approved EDR, AV, forensic, and monitoring tools by signer, path, hash, and parent process.
- Do not suppress ProcDump globally; require approved command-line and change context.
- Increase priority if followed by remote connections, new service creation, scheduled task creation, or privileged account use.
- Correlate with Defender alerts, identity anomalies, SMB/RDP/WinRM activity, and suspicious PowerShell.

## Triage steps

1. Isolate the affected device if policy allows immediate isolation for suspected credential theft.
2. Review the process tree, command line, file hash, signer, parent process, and user context.
3. Check whether the activity was authorised security testing or legitimate forensic work.
4. Review subsequent network connections, remote logons, credential use, new services, scheduled tasks, and cloud sign-ins.
5. Identify accounts logged onto the device and assess whether credentials must be reset.

## Escalation criteria

Escalate immediately to incident response when any of the following are true:

- Mimikatz, NanoDump, Dumpert, suspicious ProcDump, or comsvcs.dll dump behaviour is confirmed.
- LSASS was accessed by an unsigned, user-writable, script-launched, or suspicious process.
- The device contains privileged user sessions or administrative credentials.
- Follow-on lateral movement, remote connections, or suspicious account use is observed.
- The activity is not covered by an approved penetration test or support ticket.

## Evidence to preserve

- DeviceProcessEvents, DeviceEvents, and DeviceAlertEvents around the activity window.
- Process tree, command line, hashes, signer details, parent process, and user context.
- Any dump file path, file metadata, and quarantine status.
- Network connections and remote logons after the suspected dump.
- List of accounts with active or recent logons to the device.
- MDE investigation package or live response collection where approved.

## Containment and recovery

- Isolate the endpoint via Microsoft Defender for Endpoint.
- Disable or restrict the initiating account if compromise is likely.
- Force password reset for all accounts used on the device, prioritising privileged accounts.
- Remove tools, dump files, persistence mechanisms, and malicious scheduled tasks or services.
- Reimage or rebuild the endpoint where credential theft is confirmed or root cause is uncertain.
- Hunt for the same hash, command line, source account, and lateral movement indicators across the environment.

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | How did the attacker or tool gain execution on the endpoint? |
| Detection quality | Did the rule distinguish malicious LSASS access from EDR activity? |
| Response quality | Was isolation and credential reset completed quickly enough? |
| Scope | Were reused credentials or lateral movement identified? |
| Control improvement | Review attack surface reduction, credential guard, local admin controls, and privileged access workflows. |
