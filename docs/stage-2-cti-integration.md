# Stage 2: OpenCTI and MISP Integration

## Purpose

Add CTI ingestion and correlation so honeypot sightings can be linked to indicators, observables, vulnerabilities, malware, campaigns, intrusion sets, threat actors, reports, MISP events, Galaxy clusters, and STIX relationships.

## OpenCTI Flow

```text
OpenCTI GraphQL/API
  -> OpenCTI Connector Worker
  -> STIX Normalization Layer
  -> PostgreSQL
  -> Neo4j
  -> OpenSearch
  -> Dashboard API
```

## MISP Flow

```text
MISP REST API
  -> MISP Connector Worker
  -> Event and Attribute Parser
  -> Normalization Layer
  -> PostgreSQL
  -> Neo4j
  -> OpenSearch
  -> Dashboard API
```

## Ingested Object Types

| Source | Objects |
| --- | --- |
| OpenCTI | Indicators, observables, malware, threat actors, campaigns, intrusion sets, reports, vulnerabilities, TTPs, relationships, sightings, tags, labels, STIX objects. |
| MISP | Events, attributes, objects, tags, galaxies, galaxy clusters, sightings, correlations, warning-list matches. |

## Normalization Strategy

Create source-neutral CTI records in PostgreSQL:

- `cti_objects`: canonical object rows with type, source, external ID, name, description, confidence, labels, timestamps, and raw JSON.
- `cti_indicators`: normalized indicator values, pattern type, valid-from, valid-until, kill-chain phase, and confidence.
- `cti_relationships`: source object, relationship type, target object, confidence, start/end time, source reference.
- `cti_sightings`: sightings observed by honeypots, analysts, OpenCTI, MISP, or external feeds.

Represent the same CTI objects in Neo4j for graph analysis:

- `(:Indicator {value, type})`
- `(:ThreatActor {name})`
- `(:Campaign {name})`
- `(:Malware {name})`
- `(:Vulnerability {cve_id})`
- `(:IntrusionSet {name})`
- `(:Report {name})`
- `(:MISPEvent {uuid})`
- `(:GalaxyCluster {uuid, type})`

## Correlation Rules

| Correlation | Method |
| --- | --- |
| Honeypot attacker IP to OpenCTI indicator | Exact match on IP observable or STIX indicator pattern. |
| Honeypot attacker IP to MISP attribute | Exact match against `ip-src`, `ip-dst`, domain-resolved IP, or network attribute. |
| Suricata CVE to OpenCTI vulnerability | CVE ID match to vulnerability objects. |
| Malware hash to OpenCTI malware | Hash observable to malware or file object relationship. |
| Malware hash to MISP attribute | Exact match against `md5`, `sha1`, `sha256`, `filename|sha256`, and related object attributes. |
| ASN/country to repeated campaigns | Aggregate repeated attack patterns connected to campaigns or intrusion sets. |
| Username/password pattern to brute-force campaigns | Cluster credential reuse by source IP, ASN, time, honeypot, and service. |
| Source IP to actor infrastructure | IP indicator linked to threat actor, intrusion set, campaign, malware, or tool. |
| Honeypot sighting to CTI confidence score | Weighted score from source confidence, recency, match type, reputation, and analyst validation. |

## Risk Scoring

Recommended score range: 0-100.

| Factor | Weight |
| --- | --- |
| CTI exact indicator match | 25 |
| Known malicious reputation | 20 |
| Suricata high severity alert | 15 |
| CVE linked to known exploited vulnerability | 15 |
| Malware hash match | 15 |
| Multiple honeypots targeted | 10 |
| Mass scanner only | -15 |
| Tor/proxy only with no other signal | -5 |
| Analyst false-positive marking | -50 |

Store score components in `enrichment_results` and correlation tables so analysts can explain why an event is high risk.

## Stage 2 Dashboards

| Dashboard | Capabilities |
| --- | --- |
| CTI overview | Total indicators, active actors, campaigns, malware, CVEs, sightings, correlation rate, source freshness. |
| Indicator dashboard | Search, filter, confidence, sightings, source comparison, false-positive status. |
| Threat actor dashboard | Actor profile, related campaigns, malware, infrastructure, sightings, TTPs. |
| Malware dashboard | Families, hashes, download events, linked actors, campaigns, and reports. |
| Campaign dashboard | Campaign timeline, related infrastructure, countries, ASNs, honeypot sightings. |
| Vulnerability dashboard | CVEs, Suricata signatures, exploited services, related malware, sighting count. |
| MISP event dashboard | Event metadata, attributes, tags, galaxies, sightings, correlations. |
| OpenCTI relationship graph | D3/Neo4j-powered graph exploration with filters and path finding. |
| Honeypot-to-CTI correlation | Attacker IPs, CTI matches, confidence, reputation, event context. |
| Risk scoring | Risk distribution, high-risk events, score components, analyst review queue. |
| IOC timeline | First seen, last seen, source updates, honeypot sightings, CTI sightings. |
| Sighting dashboard | Source, count, confidence, observation time, false-positive workflow. |
| Intelligence source comparison | OpenCTI vs MISP vs honeypot vs reputation data freshness and agreement. |
| Case management | Analyst notes, status, owners, audit history, linked indicators and events. |

## Connector Design

Each connector should implement:

- Cursor-based incremental sync.
- Full backfill mode.
- Source health checks.
- Rate limit handling.
- Retries with dead-letter topics.
- Raw payload preservation.
- Source object version tracking.
- Idempotent upsert by source name and external ID.
- Normalization schema version.
- Connector audit logs.

## Analyst Workflow

1. Analyst opens a high-risk correlation finding.
2. Platform shows attack event, source IP profile, reputation, CTI matches, related campaigns, and graph context.
3. Analyst marks finding as valid, false positive, duplicate, or needs investigation.
4. Analyst can add notes, assign owner, create a case, and tag related indicators.
5. Decision updates scoring, future correlation suppression, and audit logs.
