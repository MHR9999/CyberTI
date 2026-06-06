# System Architecture

## System Name

Custom Threat Intelligence & Honeypot Analytics Platform

## High-Level Flow

```text
T-Pot Honeypot Sensors
  -> Filebeat / Logstash / Elastic Agent
  -> Redpanda or Kafka
  -> Processing Worker
  -> Enrichment Engine
  -> PostgreSQL
  -> Neo4j
  -> OpenSearch
  -> FastAPI Backend
  -> Next.js Dashboard
```

Stage 2 adds CTI connector workers:

```text
OpenCTI GraphQL/API -> CTI Connector Worker -> Normalization Layer
MISP REST API       -> MISP Connector Worker -> Normalization Layer
Normalization Layer -> PostgreSQL + Neo4j + OpenSearch -> Dashboard API
```

## Core Services

| Service | Purpose |
| --- | --- |
| T-Pot collectors | Export honeypot, Suricata, p0f, Zeek, and enrichment logs from T-Pot. |
| Ingestion gateway | Receives Logstash/Filebeat output and publishes immutable raw events to streaming topics. |
| Stream broker | Buffers event bursts and decouples sensors from processing. Redpanda is preferred for Kafka compatibility with simple operations. |
| Normalization worker | Maps source-specific T-Pot documents into the platform event schema. |
| Enrichment worker | Adds GeoIP, ASN, reputation, tor/scanner/bot categories, CVE extraction, hashes, and campaign hints. |
| PostgreSQL | System of record for normalized relational entities, dashboard filters, users, roles, audit, and review workflows. |
| Neo4j | Relationship and path analysis across IPs, ASNs, countries, honeypots, ports, credentials, malware, CVEs, indicators, actors, campaigns, and techniques. |
| OpenSearch | High-cardinality search, dashboard aggregations, raw event retention, and analyst free-text investigation. |
| Redis | Cache, WebSocket fan-out state, short-lived counters, background task coordination. |
| FastAPI backend | RBAC-protected REST and WebSocket API for dashboard, aggregation, search, notes, and review workflows. |
| Next.js frontend | Custom SOC and CTI dashboard replacing default T-Pot Kibana views. |
| Keycloak | SSO, MFA, OAuth2/OIDC, group-to-role mapping. |
| Traefik/NGINX | TLS termination, service routing, security headers, rate limiting. |
| Prometheus/Grafana/Loki | Metrics, dashboards, logs, and operational monitoring. |

## Data Zones

| Zone | Services | Network Policy |
| --- | --- | --- |
| Sensor zone | T-Pot nodes, Filebeat, Logstash | Egress only to ingestion endpoint. No database access. |
| Ingestion zone | Gateway, Redpanda/Kafka, raw event validation | Accepts signed sensor traffic; publishes streams only. |
| Processing zone | Normalization, enrichment, CTI connectors, task workers | Reads streams and external CTI APIs; writes storage layers. |
| Database zone | PostgreSQL, Neo4j, OpenSearch, Redis | No public ingress; reachable only from API/workers. |
| Application zone | FastAPI, Next.js, WebSocket gateway | Reachable from reverse proxy only. |
| Management zone | Keycloak, monitoring, admin consoles | Restricted admin access, MFA required. |

## Event Processing Pipeline

1. T-Pot exports raw logs from Honeytrap, Dionaea, Cowrie, Heralding, CiscoASA, Conpot, Tanner, Mailoney, Redishoneypot, Sentrypeer, Suricata, p0f, Zeek, and GeoIP processors.
2. Ingestion gateway validates source identity, timestamps, schema version, message size, and required event metadata.
3. Raw events are written to immutable topics such as `tpot.raw.cowrie`, `tpot.raw.suricata`, and `tpot.raw.p0f`.
4. Normalization workers map events to a canonical envelope:

```json
{
  "event_id": "uuid",
  "observed_at": "2026-06-06T05:30:00Z",
  "source_system": "tpot",
  "sensor_id": "sensor-my-dmz-01",
  "honeypot_type": "cowrie",
  "event_type": "login_attempt",
  "src_ip": "203.0.113.10",
  "src_port": 54321,
  "dst_ip": "10.10.20.5",
  "dst_port": 22,
  "protocol": "tcp",
  "username": "root",
  "password": "admin",
  "raw_ref": "opensearch://raw-tpot-2026.06.06/_doc/abc"
}
```

5. Enrichment workers add country, coordinates, ASN, reputation, tor/scanner/bot flags, CVEs, signatures, OS fingerprints, malware metadata, and confidence values.
6. Storage fan-out writes:
   - PostgreSQL for normalized entities and durable analytics.
   - Neo4j for relationship analysis and graph traversals.
   - OpenSearch for raw documents, text search, and fast aggregations.
   - Redis for dashboard counters and live feed buffers.
7. Backend API exposes time-bounded aggregation endpoints and WebSocket event streams.

## Streaming Topics

| Topic | Producer | Consumer |
| --- | --- | --- |
| `tpot.raw.*` | Ingestion gateway | Normalization workers |
| `tpot.normalized.attack_events` | Normalization workers | Enrichment workers, OpenSearch sink |
| `tpot.enriched.attack_events` | Enrichment workers | PostgreSQL sink, Neo4j sink, dashboard live feed |
| `cti.opencti.raw` | OpenCTI connector | CTI normalization |
| `cti.misp.raw` | MISP connector | MISP normalization |
| `cti.normalized.objects` | CTI normalization | PostgreSQL, Neo4j, OpenSearch sinks |
| `correlation.findings` | Correlation worker | Dashboard API, audit, case workflow |

## Storage Strategy

| Store | Data |
| --- | --- |
| PostgreSQL | Canonical relational entities, normalized attack events, users, roles, audit, dashboard filters, review state. |
| Neo4j | Connected entities and investigative relationships. |
| OpenSearch | Raw events, normalized search documents, full-text CTI records, time-series aggregations. |
| Redis | Live counters, short-lived feed cache, API throttling, Celery broker/result backend for small deployments. |

## Retention

| Data Type | Hot | Warm | Archive |
| --- | --- | --- | --- |
| Raw T-Pot logs | 30 days in OpenSearch | 180 days object storage snapshot | 1-3 years compressed |
| Normalized attack events | 180 days PostgreSQL partitions | 1 year summary tables | 3+ years aggregated |
| Graph relationships | 1 year active graph | Export old low-confidence edges | Keep CTI/high-confidence links |
| Audit logs | 1 year online | 7 years archive | Immutable storage preferred |

## Deployment Model

Use Docker Compose for initial lab and pilot deployments. Move to Kubernetes when the platform needs horizontal scaling, HA, multi-sensor ingestion, automated certificate rotation, and production-grade secrets management.

Recommended production topology:

- Minimum 3 OpenSearch nodes for production search resilience.
- PostgreSQL with physical backup, WAL archiving, and tested restore.
- Neo4j with regular dumps and export jobs.
- Redpanda/Kafka with three brokers for resilient ingestion.
- Separate worker pools for normalization, enrichment, CTI ingestion, correlation, and graph writes.
- Dedicated Keycloak database and backup plan.
