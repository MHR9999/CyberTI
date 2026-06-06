# Stage 1: T-Pot Honeypot Dashboard

## Purpose

Replace the default T-Pot dashboard with a custom SOC-facing interface that consumes live T-Pot telemetry and provides real-time attack monitoring, enrichment, ranking, and filtering.

## Data Sources

| Source | Event Types |
| --- | --- |
| Cowrie | SSH/Telnet login attempts, commands, file downloads, credentials. |
| Dionaea | Malware captures, SMB/HTTP/FTP/TFTP interactions. |
| Honeytrap | Generic service connection attempts and payload metadata. |
| Heralding | Credential collection across emulated services. |
| CiscoASA | Firewall and VPN-style attack telemetry. |
| Conpot | ICS/SCADA interaction telemetry. |
| Tanner | Web application attack and vulnerability probe telemetry. |
| Mailoney | SMTP and mail abuse telemetry. |
| Redishoneypot | Redis probes and command attempts. |
| Sentrypeer | SIP/VoIP attack telemetry. |
| Suricata | Alerts, signatures, categories, CVEs, flow metadata. |
| p0f | Passive OS fingerprints. |
| Zeek | Network protocol and connection metadata. |
| GeoIP/ASN | Country, region, city, coordinates, organization, ASN. |

## Dashboard Views

| View | Description |
| --- | --- |
| Global attack map | MapLibre world map with live arcs from source location to sensor/honeypot location. |
| Real-time attack feed | WebSocket feed of enriched events with source IP, country, ASN, service, port, honeypot, and reputation. |
| Top source IPs | Ranked IPs by attack count, distinct ports, distinct honeypots, reputation, and first/last seen. |
| Top countries | Country ranking by event volume, unique IPs, honeypots touched, and trend. |
| Top ASNs | ASN ranking with organization, count, unique IPs, reputation mix, and campaign links. |
| Attack volume over time | ECharts time-series with event counts by minute/hour/day and event type. |
| Honeypot distribution | Donut/bar chart by honeypot type and sensor. |
| Destination port histogram | Histogram and ranked table for ports and service names. |
| Protocol/service statistics | TCP/UDP/application protocol breakdown. |
| Username tag cloud | D3 tag cloud from login attempts with filters. |
| Password tag cloud | D3 tag cloud from credential attempts with sensitivity controls. |
| p0f OS fingerprints | OS family/version distribution. |
| Suricata categories | Alert category breakdown by time and severity. |
| Suricata CVE top 10 | CVE extraction from signatures and metadata. |
| Suricata signature top 10 | Signature rankings with SID, category, severity, and event count. |
| Reputation overview | Known attacker, unknown, benign, suspicious, malicious, tor, scanner, bot, and proxy categories. |
| Mass scanner/bot/tor categorization | Classification panel from reputation and behavior rules. |

## Global Filters

- Time range
- Country
- Honeypot
- Sensor
- Destination port
- Protocol
- ASN
- Reputation
- Source IP
- CVE
- Suricata signature
- Username
- Password
- Known scanner/bot/tor flag

## Frontend Layout

Use a dense SOC dashboard layout rather than a marketing page:

- Left navigation: Overview, Attack Map, Sources, Honeypots, Credentials, Suricata, Reputation, Search, Graph, Settings.
- Top filter bar: time range, country, honeypot, port, protocol, ASN, reputation, source IP.
- Main overview grid:
  - attack map
  - live attack feed
  - attack volume
  - top source IPs
  - top countries
  - top ASNs
  - honeypot distribution
  - port histogram
  - Suricata top signatures
  - credential tag clouds

## Backend API Requirements

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/overview/summary` | KPI totals and deltas for the selected time range. |
| `GET /api/v1/attacks` | Paginated enriched attack events. |
| `GET /api/v1/attacks/top-sources` | Top attacking IPs. |
| `GET /api/v1/attacks/top-countries` | Top countries. |
| `GET /api/v1/attacks/top-asns` | Top ASNs. |
| `GET /api/v1/attacks/timeseries` | Attack volume over time. |
| `GET /api/v1/honeypots/distribution` | Honeypot attack distribution. |
| `GET /api/v1/ports/histogram` | Destination port histogram. |
| `GET /api/v1/credentials/usernames` | Username tag cloud source data. |
| `GET /api/v1/credentials/passwords` | Password tag cloud source data. |
| `GET /api/v1/suricata/categories` | Alert category aggregation. |
| `GET /api/v1/suricata/cves/top` | Top CVEs. |
| `GET /api/v1/suricata/signatures/top` | Top signatures. |
| `GET /api/v1/reputation/summary` | Known/unknown/malicious/scanner/tor/bot distribution. |
| `WS /api/v1/live/attacks` | Real-time enriched attack feed. |

## Normalized Event Fields

| Field | Type | Description |
| --- | --- | --- |
| `event_id` | UUID | Platform event ID. |
| `source_system` | text | `tpot`, `opencti`, `misp`, or connector name. |
| `source_index` | text | Original Elasticsearch/OpenSearch index. |
| `sensor_id` | text | T-Pot sensor identifier. |
| `honeypot_id` | UUID | Internal honeypot entity. |
| `honeypot_type` | text | Cowrie, Dionaea, Suricata, etc. |
| `observed_at` | timestamptz | Event observation time. |
| `ingested_at` | timestamptz | Platform ingestion time. |
| `event_type` | text | Login attempt, connection, alert, malware download, etc. |
| `src_ip` | inet | Attacker/source IP. |
| `src_port` | integer | Source port. |
| `dst_ip` | inet | Destination IP. |
| `dst_port` | integer | Destination port. |
| `protocol` | text | TCP, UDP, HTTP, SSH, SIP, etc. |
| `username` | text | Observed username where applicable. |
| `password` | text | Observed password where applicable. |
| `payload_hash` | text | Hash of payload or malware. |
| `suricata_signature_id` | integer | Suricata SID. |
| `suricata_signature` | text | Signature text. |
| `suricata_category` | text | Alert category. |
| `cve_ids` | text array | Extracted CVE IDs. |
| `p0f_os` | text | Passive OS fingerprint. |
| `raw_event` | jsonb | Source event snapshot. |

## Enrichment Rules

- GeoIP: country, region, city, latitude, longitude, timezone.
- ASN: ASN number, name, organization, route.
- Reputation: known attacker, malicious, suspicious, benign, unknown.
- Category flags: mass scanner, bot, tor exit node, proxy/VPN, cloud provider, residential ISP.
- CVE extraction: parse Suricata signatures and metadata for CVE identifiers.
- Credential classification: default credentials, weak credentials, device/vendor pattern, campaign reuse.
- Behavioral features: unique ports, unique honeypots, attack rate, burst score, first seen, last seen.
- Confidence score: weighted score from reputation, CTI matches, behavior, alert severity, and recurrence.

## Implementation Notes

- Partition `attack_events` by `observed_at` monthly or weekly depending on volume.
- Use materialized views or rollup tables for dashboard-heavy aggregations.
- Use OpenSearch for exploratory search and PostgreSQL for authoritative counts.
- Push live events via WebSocket from Redis stream or Kafka consumer group.
- Avoid showing raw passwords to Viewer roles; hash, mask, or restrict sensitive values.
