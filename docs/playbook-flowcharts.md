# Visual Playbook Flowcharts

Use Mermaid diagrams to make response logic easy to follow during live operations. Each flowchart should help an analyst answer five operating questions:

1. What triggered the alert?
2. What are the first three checks?
3. What evidence must be preserved?
4. When do I escalate?
5. What action is safe to take immediately?

## Mermaid usage

GitHub renders Mermaid diagrams directly in Markdown. Keep diagrams simple, use `flowchart TD`, and use decision diamonds for escalation criteria.

## UC-IDENTITY-001 MFA Fatigue Attack

```mermaid
flowchart TD
    A[Alert triggered: more than 5 MFA failures in 15 minutes followed by success] --> B[Check 1: review failed and successful sign-in timeline]
    B --> C[Check 2: compare IP, location, device compliance, and app]
    C --> D[Check 3: contact user to confirm MFA approval]
    D --> E[Preserve evidence: SigninLogs, Authenticator request records, CorrelationId, IP, location, device detail]
    E --> F{User denies approval or cannot be reached?}
    F -- Yes --> G[Escalate to incident response]
    F -- No --> H{Privileged user or suspicious geography?}
    H -- Yes --> G
    H -- No --> I{Post-auth activity found?}
    I -- Yes --> G
    I -- No --> J[Safe immediate action: revoke sessions and require MFA step-up]
    G --> K[Containment: disable account, revoke sessions, force password reset, require MFA re-registration]
    J --> L[Close or monitor with tuning notes]
    K --> M[Recovery and lessons learned]
```

## UC-IDENTITY-002 Malicious OAuth App Consent

```mermaid
flowchart TD
    A[Alert triggered: OAuth consent with high-risk permissions] --> B[Check 1: identify app, AppId, publisher, permissions, and consent type]
    B --> C[Check 2: verify approval through IT, security, procurement, or data owner]
    C --> D[Check 3: review initiating user role, sign-ins, and post-consent app activity]
    D --> E[Preserve evidence: AuditLogs event, TargetResources, AppId, permissions, publisher, approval record]
    E --> F{App unapproved or publisher suspicious?}
    F -- Yes --> G[Escalate to incident response]
    F -- No --> H{Admin consent or tenant-wide access?}
    H -- Yes --> G
    H -- No --> I{Mail, file, or directory access observed?}
    I -- Yes --> G
    I -- No --> J[Safe immediate action: request owner validation and monitor app activity]
    G --> K[Containment: revoke consent, block AppId, remove service principal, revoke user sessions if needed]
    J --> L[Close as authorised or raise governance tuning action]
    K --> M[Recovery and lessons learned]
```

## UC-CLOUD-001 Impossible Travel

```mermaid
flowchart TD
    A[Alert triggered: successful sign-ins from distant locations at unrealistic speed] --> B[Check 1: validate both sign-ins, IPs, locations, apps, and time delta]
    B --> C[Check 2: check VPN, proxy, secure web gateway, and travel context]
    C --> D[Check 3: contact user and review Entra ID risk score]
    D --> E[Preserve evidence: SigninLogs, AADNonInteractiveUserSignInLogs, IPs, geolocation, device, CA result, VPN logs]
    E --> F{User cannot validate one sign-in?}
    F -- Yes --> G[Escalate to incident response]
    F -- No --> H{Privileged user, high risk, or unmanaged device?}
    H -- Yes --> G
    H -- No --> I{Suspicious post-sign-in activity?}
    I -- Yes --> G
    I -- No --> J[Safe immediate action: revoke sessions or require MFA step-up if risk remains]
    G --> K[Containment: conditional revocation, password reset, session invalidation, access review]
    J --> L[Close as VPN or travel false positive with evidence]
    K --> M[Recovery and lessons learned]
```

## UC-EMAIL-001 Phishing Credential Harvest

```mermaid
flowchart TD
    A[Alert triggered: phishing email with ClickAllowed URL event] --> B[Check 1: review sender, recipient, subject, URL, threat type, and click time]
    B --> C[Check 2: safely analyse URL and determine whether credentials were submitted]
    C --> D[Check 3: check Entra ID for post-click sign-in anomalies]
    D --> E[Preserve evidence: headers, NetworkMessageId, URL, click event, sandbox report, user statement, sign-in logs]
    E --> F{Credentials entered, MFA approved, or OAuth consent granted?}
    F -- Yes --> G[Escalate to incident response]
    F -- No --> H{Multiple users targeted or clicked?}
    H -- Yes --> G
    H -- No --> I{URL confirmed malicious and still reachable?}
    I -- Yes --> G
    I -- No --> J[Safe immediate action: soft-delete email and block URL or sender under email policy]
    G --> K[Containment: remove messages, block sender and URL, reset password if needed, revoke sessions]
    J --> L[Close or monitor campaign with awareness notes]
    K --> M[Recovery and lessons learned]
```

## UC-ENDPOINT-001 Possible LSASS Credential Dump

```mermaid
flowchart TD
    A[Alert triggered: known dump tool or suspicious LSASS process access] --> B[Check 1: review process tree, command line, hash, signer, and parent process]
    B --> C[Check 2: confirm whether activity matches approved AV, EDR, forensic, or pen-test work]
    C --> D[Check 3: check lateral movement, remote logons, new services, and network connections]
    D --> E[Preserve evidence: DeviceProcessEvents, DeviceEvents, DeviceAlertEvents, process tree, hash, command line, accounts logged on]
    E --> F{Known dumping tool or unauthorised LSASS access?}
    F -- Yes --> G[Escalate immediately to incident response]
    F -- No --> H{Privileged credentials present on device?}
    H -- Yes --> G
    H -- No --> I{Follow-on lateral movement indicators?}
    I -- Yes --> G
    I -- No --> J[Safe immediate action: collect evidence and request senior review before destructive changes]
    G --> K[Containment: isolate endpoint, disable account, reset credentials used on device]
    J --> L[Close as authorised tool or tune allowlist with evidence]
    K --> M[Recovery: remove tooling, rebuild if needed, hunt across estate, lessons learned]
```

## Playbook quality checklist

| Check | Yes/No | Notes |
| --- | --- | --- |
| Trigger condition is clear. |  |  |
| First three analyst checks are clear. |  |  |
| Evidence preservation step exists before closure or containment. |  |  |
| Decision diamonds identify escalation criteria. |  |  |
| Safe immediate action is documented. |  |  |
| Closure, containment, and recovery paths are clear. |  |  |
| Irreversible actions require approval or policy reference. |  |  |
| Diagram renders correctly in GitHub. |  |  |

## Diagram style guide

- Use short node labels.
- Use decision nodes for `Yes/No` paths.
- Keep each diagram focused on one incident type.
- Link each flowchart to a written procedure and detection record.
- Avoid putting secrets, customer names, or real incident details in diagrams.
