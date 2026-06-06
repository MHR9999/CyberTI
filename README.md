# Custom Threat Intelligence & Honeypot Analytics Platform

Enterprise-grade open-source threat intelligence system for replacing the default T-Pot dashboard with a custom analytics platform, then extending it with OpenCTI and MISP correlation.

## Objectives

- Centralize T-Pot honeypot telemetry, Suricata alerts, p0f fingerprints, GeoIP, reputation, malware, and credential observations.
- Deliver a custom real-time dashboard for SOC and CTI analysts.
- Store normalized events in PostgreSQL, graph relationships in Neo4j, and searchable telemetry in OpenSearch.
- Integrate OpenCTI and MISP for indicator, malware, campaign, actor, vulnerability, and sighting analysis.
- Provide enterprise controls: SSO, MFA, RBAC, audit logging, API keys, TLS, segmentation, monitoring, and secure operations.

## Architecture Package

- [System Architecture](docs/architecture.md)
- [Stage 1 T-Pot Dashboard](docs/stage-1-tpot-dashboard.md)
- [Stage 2 OpenCTI and MISP Integration](docs/stage-2-cti-integration.md)
- [Security Architecture](docs/security-architecture.md)
- [Implementation Roadmap](docs/implementation-roadmap.md)
- [API Contract](api/openapi.yaml)
- [PostgreSQL Schema](database/postgres_schema.sql)
- [Neo4j Graph Model](graph/neo4j_model.cypher)
- [Docker Compose Skeleton](deploy/docker-compose.yml)
- [Environment Template](deploy/.env.example)

## Recommended Stack

| Layer | Technology |
| --- | --- |
| Frontend | Next.js, React, Tailwind CSS, MapLibre, ECharts, D3.js |
| Backend API | FastAPI |
| Streaming | Redpanda or Kafka; Redis Streams for smaller deployments |
| Relational storage | PostgreSQL |
| Graph analysis | Neo4j Community Edition |
| Search and analytics | OpenSearch |
| Cache and queues | Redis, Celery |
| Authentication | Keycloak |
| Reverse proxy | Traefik or NGINX |
| Monitoring | Prometheus, Grafana, Loki, OpenTelemetry |
| Packaging | Docker Compose first, Kubernetes later |
| Secrets | Docker secrets first; Vault or SOPS for production |

## Stage Roadmap

1. **Stage 1: T-Pot dashboard replacement**
   - Ingest from T-Pot Elasticsearch or Logstash.
   - Normalize honeypot, Suricata, p0f, Zeek, GeoIP, ASN, credential, and malware events.
   - Stream real-time events to the dashboard.
   - Store normalized records in PostgreSQL, relationships in Neo4j, and searchable documents in OpenSearch.

2. **Stage 2: CTI integration**
   - Ingest OpenCTI through GraphQL/API connectors.
   - Ingest MISP events and attributes through REST connectors.
   - Normalize STIX, MISP attributes, sightings, labels, galaxy clusters, malware, campaigns, vulnerabilities, and relationships.
   - Correlate honeypot observations with CTI indicators and confidence scores.

3. **Enterprise hardening**
   - Enforce SSO, MFA, RBAC, API keys, TLS, audit logs, and network segmentation.
   - Add analyst workflows for false-positive review, notes, case management, and intelligence source comparison.
