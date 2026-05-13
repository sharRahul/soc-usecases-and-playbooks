# Visual Playbook Flowcharts

Use Mermaid diagrams to make response logic easy to follow during live operations. Each playbook should include a decision tree that shows triage, escalation, containment, communication, and closure paths.

## Mermaid usage

GitHub renders Mermaid diagrams directly in Markdown. Keep diagrams simple enough for an analyst to follow quickly.

## Generic alert response flow

```mermaid
flowchart TD
    A[Alert triggered] --> B[Validate alert context]
    B --> C[Check related activity]
    C --> D[Assess affected user or asset criticality]
    D --> E{Evidence of compromise?}
    E -- Yes --> F[Escalate to incident response]
    E -- No --> G{Benign authorised activity?}
    G -- Yes --> H[Close as true positive benign]
    G -- No --> I{Detection tuning issue?}
    I -- Yes --> J[Close as false positive and raise tuning action]
    I -- No --> K[Monitor or request senior review]
    F --> L[Preserve evidence]
    L --> M{Containment approved or required?}
    M -- Yes --> N[Contain affected account/device/workload]
    M -- No --> O[Continue investigation]
    N --> P[Recovery and lessons learned]
    O --> P
```

## Identity compromise playbook

```mermaid
flowchart TD
    A[Identity alert triggered] --> B[Review sign-in timeline]
    B --> C[Check MFA, device, CA result, IP, location]
    C --> D{Privileged or VIP user?}
    D -- Yes --> E[Escalate immediately to senior analyst]
    D -- No --> F{Successful suspicious sign-in?}
    F -- Yes --> G[Preserve sign-in logs and session details]
    F -- No --> H{Repeated failures only?}
    H -- Yes --> I[Check password spray pattern]
    H -- No --> J[Continue enrichment]
    E --> K{User confirms activity?}
    G --> K
    K -- No or unreachable --> L[Reset password, revoke sessions, require MFA reset]
    K -- Yes --> M[Close as benign with evidence]
    L --> N[Check mailbox, endpoint, and app consent activity]
    N --> O{Secondary compromise indicators?}
    O -- Yes --> P[Declare incident]
    O -- No --> Q[Monitor and close after review]
```

## Phishing response playbook

```mermaid
flowchart TD
    A[Phishing alert or user report] --> B[Review message headers, sender, URLs, attachments]
    B --> C[Check delivery scope across tenant]
    C --> D{User clicked or submitted credentials?}
    D -- Yes --> E[Escalate as suspected compromise]
    D -- No --> F{Malware or confirmed malicious URL?}
    F -- Yes --> G[Quarantine messages and block indicators]
    F -- No --> H{Bulk campaign?}
    H -- Yes --> I[Hunt for similar messages and notify users]
    H -- No --> J[Close or monitor]
    E --> K[Reset credentials and revoke sessions]
    K --> L[Review mailbox rules and forwarding]
    G --> M[Preserve message evidence]
    I --> M
    M --> N[Update detection and awareness notes]
```

## Endpoint malware or suspicious process playbook

```mermaid
flowchart TD
    A[Endpoint alert triggered] --> B[Review device timeline]
    B --> C[Capture process tree, command line, hash, network activity]
    C --> D{Known malicious or high-confidence EDR alert?}
    D -- Yes --> E[Isolate device if approved by policy]
    D -- No --> F{Suspicious but unclear?}
    F -- Yes --> G[Collect additional telemetry and request senior review]
    F -- No --> H[Close with tuning note if benign]
    E --> I[Preserve evidence and create incident ticket]
    G --> J{Credential access, persistence, or lateral movement?}
    J -- Yes --> I
    J -- No --> K[Monitor and close after validation]
    I --> L[Run containment, eradication, and recovery steps]
    L --> M[Lessons learned and detection improvement]
```

## Cloud admin activity playbook

```mermaid
flowchart TD
    A[Cloud admin alert triggered] --> B[Identify principal, action, target, source IP]
    B --> C[Check change ticket or approval]
    C --> D{Approved change?}
    D -- Yes --> E[Close as authorised with evidence]
    D -- No --> F{Privileged or security-impacting action?}
    F -- Yes --> G[Escalate to incident response]
    F -- No --> H[Request owner validation]
    G --> I[Preserve audit logs and role assignment history]
    I --> J{Control disabled or data exposed?}
    J -- Yes --> K[Contain account, revert change, assess impact]
    J -- No --> L[Monitor and complete investigation]
    H --> M{Owner validates activity?}
    M -- Yes --> E
    M -- No --> G
```

## Playbook quality checklist

| Check | Yes/No | Notes |
| --- | --- | --- |
| Trigger condition is clear. |  |  |
| First analyst action is obvious. |  |  |
| VIP, privileged, or critical asset branch exists. |  |  |
| Evidence preservation step exists before closure or containment. |  |  |
| Escalation criteria are explicit. |  |  |
| Closure categories are clear. |  |  |
| Irreversible actions require approval or policy reference. |  |  |
| Diagram renders correctly in GitHub. |  |  |

## Diagram style guide

- Use short node labels.
- Use decision nodes for `Yes/No` paths.
- Keep each diagram focused on one incident type.
- Link each flowchart to a written procedure and detection record.
- Avoid putting secrets, customer names, or real incident details in diagrams.
