# Implementation Roadmap

## Phase 0: Foundation

Deliverables:

- Repository structure for frontend, backend, workers, database migrations, and deployment manifests.
- Docker Compose lab environment for PostgreSQL, Redis, Redpanda, OpenSearch, Neo4j, Keycloak, API, frontend, and workers.
- OpenTelemetry baseline for API and workers.
- CI checks for linting, tests, schema validation, and container builds.

Acceptance criteria:

- Local stack starts from a clean checkout.
- API can authenticate a Keycloak user.
- PostgreSQL schema and Neo4j constraints apply successfully.
- Health endpoints report dependency status.

## Phase 1: T-Pot Ingestion

Deliverables:

- Logstash/Filebeat output from T-Pot to ingestion gateway or Redpanda/Kafka.
- Source-specific parsers for Cowrie, Dionaea, Honeytrap, Heralding, CiscoASA, Conpot, Tanner, Mailoney, Redishoneypot, Sentrypeer, Suricata, p0f, and optional Zeek.
- Canonical attack event schema and normalization tests.
- Dead-letter topic for invalid or unsupported events.

Acceptance criteria:

- Raw T-Pot events are preserved in OpenSearch.
- Normalized events are written to PostgreSQL.
- Unsupported event types are captured with reason codes.
- Ingestion lag and parse error rate are visible in monitoring.

## Phase 2: Enrichment and Storage

Deliverables:

- GeoIP and ASN enrichment.
- Reputation enrichment with known attacker, unknown, malicious, suspicious, tor, scanner, bot, and proxy/VPN categories.
- Suricata CVE extraction and signature normalization.
- Credential and malware download normalization.
- Neo4j graph writer for IP, country, ASN, honeypot, port, protocol, credential, malware hash, CVE, and Suricata signature relationships.

Acceptance criteria:

- Enriched events include country, ASN, reputation, risk score, and source explanation.
- Dashboard aggregations return consistent counts from PostgreSQL/OpenSearch.
- Graph queries can answer: which IPs attacked a honeypot, which ASNs target a port, which IPs triggered a CVE-linked signature.

## Phase 3: Custom Dashboard

Deliverables:

- Next.js dashboard shell with RBAC-aware navigation.
- Global filter bar for time range, country, honeypot, port, protocol, ASN, reputation, and source IP.
- MapLibre attack map.
- Live attack feed over WebSocket.
- ECharts/D3 panels for top IPs, countries, ASNs, attack volume, honeypot distribution, port histogram, protocol statistics, username cloud, password cloud, p0f OS distribution, Suricata categories, CVEs, and signatures.
- Role-based masking of sensitive credential values.

Acceptance criteria:

- Dashboard updates live without page refresh.
- All required Stage 1 filters apply across supported panels.
- Viewer role cannot see raw passwords or raw event payloads.
- SOC Analyst role can drill from a chart into event search.

## Phase 4: OpenCTI Integration

Deliverables:

- OpenCTI connector with incremental sync and backfill.
- STIX object normalization.
- Indicator, observable, malware, threat actor, campaign, intrusion set, report, vulnerability, TTP, relationship, sighting, tag, and label support.
- CTI object graph projection into Neo4j.

Acceptance criteria:

- OpenCTI objects are idempotently upserted by source and external ID.
- OpenCTI relationships are queryable in graph views.
- Honeypot IPs, hashes, CVEs, and sightings correlate against OpenCTI data.

## Phase 5: MISP Integration

Deliverables:

- MISP connector with incremental sync and backfill.
- Event, attribute, object, tag, galaxy, cluster, sighting, and correlation parser.
- Warning-list and false-positive handling.
- Source comparison between MISP, OpenCTI, reputation feeds, and honeypot sightings.

Acceptance criteria:

- MISP attributes correlate to honeypot IPs, domains, URLs, hashes, and CVEs.
- MISP events are visible in a dedicated dashboard.
- Analyst decisions can suppress false positives without deleting source intelligence.

## Phase 6: Analyst Workflow

Deliverables:

- Correlation finding queue.
- Risk scoring details and score components.
- Analyst notes.
- Case ownership and status.
- False-positive, duplicate, valid, and needs-investigation review states.
- Full audit trail.

Acceptance criteria:

- Every analyst decision creates an audit record.
- Risk score explanation is visible for each finding.
- Reviewed false positives reduce future alert noise without hiding raw events.

## Phase 7: Production Hardening

Deliverables:

- TLS everywhere.
- MFA enforcement through Keycloak.
- API key lifecycle management.
- Backup and restore playbooks.
- Retention policies.
- Secrets management with Vault or SOPS.
- Network segmentation and firewall rules.
- Kubernetes manifests or Helm charts if scale requires it.

Acceptance criteria:

- Restore test succeeds from backups.
- Admin and analyst actions are auditable.
- Service accounts have least-privilege access.
- Ingestion remains stable during burst traffic.
