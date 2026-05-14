# Threat Intelligence Integration Guide

This guide explains how to enrich SOC use cases with threat intelligence in Microsoft Sentinel. It focuses on MISP feeds, Microsoft Defender Threat Intelligence, watchlists, and KQL correlation patterns that can be adapted for email, identity, cloud, endpoint, and network detections.

## Objectives

Use threat intelligence to:

- Prioritise alerts involving known malicious infrastructure.
- Enrich triage with indicator type, confidence score, source, and expiry.
- Detect matches between internal telemetry and external indicators of compromise.
- Support repeatable evidence capture for incident response and assurance reviews.

## Data sources and prerequisites

| Component | Purpose |
| --- | --- |
| Microsoft Sentinel workspace | Central SIEM workspace where analytics rules and TI tables are queried. |
| ThreatIntelligenceIndicator table | Stores ingested indicators such as domains, URLs, IP addresses, file hashes, and confidence scores. |
| MISP | External or internal threat intelligence platform providing indicators through TAXII, API export, or scheduled feed export. |
| Microsoft Defender Threat Intelligence connector | Provides Microsoft TI indicators or enrichment depending on available licensing and connector configuration. |
| Watchlists | Store locally curated indicators, approved allowlists, or high-priority campaign indicators. |

## Connect Microsoft Sentinel Threat Intelligence to MISP feeds

Use a controlled integration pattern. Do not ingest every available feed without expiry, confidence, and source controls.

### Recommended approach

1. In Microsoft Sentinel, open the target workspace.
2. Go to **Content hub** or **Data connectors** and search for threat intelligence or TAXII/STIX connectors available in your tenant.
3. Configure the connector to ingest indicators from the MISP feed endpoint where TAXII/STIX is available.
4. If your MISP deployment does not expose a supported TAXII endpoint, export MISP indicators to STIX/TAXII through a supported bridge, automation job, Logic App, or ingestion pipeline.
5. Use dedicated API credentials with minimum required permissions.
6. Apply feed hygiene controls before production ingestion:
   - Indicator type must be clear, such as domain, URL, IP, email sender, or file hash.
   - Confidence score should be present where possible.
   - Expiry time should be populated and enforced.
   - Internal allowlists should override known business domains and security tooling.
7. Validate that indicators appear in `ThreatIntelligenceIndicator` and include useful fields such as `IndicatorType`, `DomainName`, `Url`, `NetworkIP`, `FileHashValue`, `ConfidenceScore`, `SourceSystem`, and `ExpirationDateTime`.

### Operational notes

- Keep MISP feed ownership documented so analysts know who to contact when a feed creates noise.
- Prefer high-confidence, time-bound campaign indicators over large generic blocklists.
- Review expired indicators and ingestion failures during the monthly SOC metrics review.
- Use watchlists for local suppressions, priority indicators, and environment-specific context.

## Use the Sentinel TI data connector for Microsoft Defender Threat Intelligence

Microsoft Defender Threat Intelligence can be used as a Sentinel enrichment source where the connector and licensing are available in the tenant.

Recommended implementation steps:

1. In Microsoft Sentinel, open the target workspace.
2. Go to **Content hub** or **Data connectors** and search for Microsoft Defender Threat Intelligence.
3. Enable the connector using an account with the required Sentinel and tenant permissions.
4. Confirm which indicator types are available in your licensing tier and connector configuration.
5. Validate ingestion by querying recent indicators in the workspace.
6. Build analytics rules that join internal telemetry to high-confidence, active indicators.
7. Add suppression logic for known internal systems, approved SaaS providers, and security vendor infrastructure.

Validation query:

```kql
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(24h)
| summarize IndicatorCount=count() by IndicatorType, SourceSystem
| order by IndicatorCount desc
```

## Watchlist-based detection pattern

Use Sentinel watchlists when the SOC needs local control over indicators, priority campaigns, business allowlists, or temporary incident indicators.

Example watchlist columns:

| Column | Purpose |
| --- | --- |
| Indicator | Domain, URL, IP address, email sender, or hash. |
| IndicatorType | Domain, URL, IP, Email, Hash. |
| ConfidenceScore | Analyst-assigned confidence score from 0 to 100. |
| Source | MISP, Defender TI, ISAC, vendor report, incident response, or analyst research. |
| ExpiryDate | Date the indicator should stop being used unless renewed. |
| Notes | Brief context for triage. |

Example KQL pattern for email sender domains:

```kql
let LocalIOCWatchlist = _GetWatchlist('SOC_IOC_Watchlist')
| where IndicatorType =~ "Domain"
| where todatetime(ExpiryDate) > now()
| where toint(ConfidenceScore) > 70
| project IOC_Domain=tolower(Indicator), IOC_Confidence=toint(ConfidenceScore), IOC_Source=Source, IOC_Notes=Notes;
EmailEvents
| where Timestamp >= ago(7d)
| extend SenderDomain=tolower(SenderFromDomain)
| join kind=inner LocalIOCWatchlist on $left.SenderDomain == $right.IOC_Domain
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderDomain, Subject, NetworkMessageId, DeliveryAction, IOC_Confidence, IOC_Source, IOC_Notes
```

## Correlate ThreatIntelligenceIndicator with use-case data sources

Use this pattern when indicators are stored in `ThreatIntelligenceIndicator` and the use case data source contains comparable entities.

### Email sender domain correlation

This query correlates Defender for Office 365 sender domains against high-confidence TI domains.

```kql
let TI_Domains = ThreatIntelligenceIndicator
| where TimeGenerated >= ago(14d)
| where Active == true
| where ExpirationDateTime > now()
| where ConfidenceScore > 70
| where isnotempty(DomainName)
| summarize arg_max(TimeGenerated, *) by DomainName
| project IOC_Domain=tolower(DomainName), ConfidenceScore, ThreatType, Description, SourceSystem, ExpirationDateTime;
EmailEvents
| where Timestamp >= ago(7d)
| extend SenderDomain=tolower(SenderFromDomain)
| join kind=inner TI_Domains on $left.SenderDomain == $right.IOC_Domain
| project AlertTime=Timestamp, RecipientEmailAddress, SenderFromAddress, SenderDomain, Subject, NetworkMessageId, DeliveryAction, ConfidenceScore, ThreatType, SourceSystem, Description, ExpirationDateTime
```

### URL click correlation

```kql
let TI_Urls = ThreatIntelligenceIndicator
| where TimeGenerated >= ago(14d)
| where Active == true
| where ExpirationDateTime > now()
| where ConfidenceScore > 70
| where isnotempty(Url)
| summarize arg_max(TimeGenerated, *) by Url
| project IOC_Url=tolower(Url), ConfidenceScore, ThreatType, Description, SourceSystem, ExpirationDateTime;
UrlClickEvents
| where Timestamp >= ago(7d)
| extend ClickedUrl=tolower(Url)
| join kind=inner TI_Urls on $left.ClickedUrl == $right.IOC_Url
| project AlertTime=Timestamp, AccountUpn, Url, ActionType, IPAddress, NetworkMessageId, ConfidenceScore, ThreatType, SourceSystem, Description, ExpirationDateTime
```

### Sign-in IP correlation

```kql
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated >= ago(14d)
| where Active == true
| where ExpirationDateTime > now()
| where ConfidenceScore > 70
| where isnotempty(NetworkIP)
| summarize arg_max(TimeGenerated, *) by NetworkIP
| project IOC_IP=NetworkIP, ConfidenceScore, ThreatType, Description, SourceSystem, ExpirationDateTime;
SigninLogs
| where TimeGenerated >= ago(7d)
| join kind=inner TI_IPs on $left.IPAddress == $right.IOC_IP
| project AlertTime=TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, LocationDetails, ConditionalAccessStatus, ConfidenceScore, ThreatType, SourceSystem, Description, ExpirationDateTime
```

### Endpoint hash correlation

```kql
let TI_Hashes = ThreatIntelligenceIndicator
| where TimeGenerated >= ago(14d)
| where Active == true
| where ExpirationDateTime > now()
| where ConfidenceScore > 70
| where isnotempty(FileHashValue)
| summarize arg_max(TimeGenerated, *) by FileHashValue
| project IOC_Hash=tolower(FileHashValue), ConfidenceScore, ThreatType, Description, SourceSystem, ExpirationDateTime;
DeviceProcessEvents
| where Timestamp >= ago(7d)
| extend ProcessHash=tolower(SHA256)
| where isnotempty(ProcessHash)
| join kind=inner TI_Hashes on $left.ProcessHash == $right.IOC_Hash
| project AlertTime=Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, SHA256, ConfidenceScore, ThreatType, SourceSystem, Description, ExpirationDateTime
```

## Analytics rule guidance

When converting TI joins into Sentinel analytics rules:

- Use only active, unexpired indicators.
- Prefer `ConfidenceScore > 70` for alerting and lower scores for hunting.
- Include indicator source and description in alert entities or custom details.
- Apply allowlists for internal domains, approved SaaS, vulnerability scanners, email gateways, and security tools.
- Keep joins narrow and time-bound to reduce query cost and noise.
- Route alerts by use case severity, asset criticality, and indicator confidence.

## Analyst triage guidance

For every TI match, analysts should confirm:

1. What matched: domain, URL, IP, sender, or hash.
2. Why the indicator is trusted: source, confidence score, age, and expiry.
3. Whether the matched internal activity was inbound, outbound, clicked, executed, or authenticated.
4. Whether the activity is blocked, allowed, quarantined, or successful.
5. Whether additional containment is safe under the relevant use-case playbook.

## Governance and hygiene

| Control | Guidance |
| --- | --- |
| Feed review | Review feed value, volume, and false positives monthly. |
| Indicator expiry | Do not use indicators without expiry for high-volume alerting unless explicitly risk-accepted. |
| Allowlisting | Store allowlists separately and review them quarterly. |
| Evidence | Preserve matched indicator record, source telemetry, confidence score, and query result. |
| Change control | Record connector, parser, and watchlist changes in the SOC change process. |
| Privacy | Do not upload sensitive internal incident details to external TI platforms unless approved. |

## Example use-case integrations

| Use case | Useful TI enrichment |
| --- | --- |
| UC-IDENTITY-001-MFA-Fatigue-Attack | Match sign-in IPs against high-confidence malicious IP indicators. |
| UC-IDENTITY-002-Malicious-OAuth-App-Consent | Match app publisher domains, reply URLs, or hosting IPs against TI. |
| UC-CLOUD-001-Impossible-Travel | Match source IPs against VPN, hosting, TOR, botnet, or anonymising infrastructure indicators. |
| UC-EMAIL-001-Phishing-Credential-Harvest | Match sender domains, URLs, and clicked domains against TI. |
| UC-ENDPOINT-001-Possible-LSASS-Credential-Dump | Match process hashes, download URLs, and command-and-control IPs against TI. |
