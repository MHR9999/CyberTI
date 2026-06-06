# Security Architecture

## Identity and Access

Use Keycloak as the primary identity provider.

| Control | Design |
| --- | --- |
| SSO | OIDC/OAuth2 through Keycloak. |
| MFA | Required for Admin, Auditor, SOC Analyst, and CTI Analyst roles. |
| RBAC | Application roles mapped from Keycloak groups and stored locally for audit stability. |
| Session handling | Short access tokens, refresh token rotation, secure cookies for browser sessions. |
| API keys | Scoped keys for sensors, connectors, and automation. Store only hashed API keys. |

## Roles

| Role | Permissions |
| --- | --- |
| Admin | Platform configuration, users, roles, API keys, integrations, retention, all data. |
| SOC Analyst | Read attack dashboards, investigate events, create notes, manage cases. |
| CTI Analyst | Read and manage CTI data, validate correlations, tune scoring, manage false positives. |
| Viewer | Read dashboards with sensitive fields masked. No raw password or API access. |
| Auditor | Read audit logs, user activity, configuration changes, and access reports. |

## Sensitive Data Handling

- Mask passwords by default in the UI.
- Store credential observations as normalized rows with optional salted hashes for trend analysis.
- Restrict raw event access to Admin, SOC Analyst, and CTI Analyst.
- Avoid logging secrets, tokens, raw API keys, or full Authorization headers.
- Use field-level redaction in API responses based on role.

## Network Segmentation

| Segment | Allowed Traffic |
| --- | --- |
| Sensor to ingestion | HTTPS or mTLS Logstash/Filebeat traffic only. |
| Ingestion to broker | Broker publish only. |
| Workers to stores | PostgreSQL, Neo4j, OpenSearch, Redis access by service account. |
| API to stores | Read/write only through least-privilege database users. |
| Frontend to API | HTTPS through reverse proxy only. |
| Management | Admin access through VPN or private network, MFA enforced. |

## TLS

- TLS at the reverse proxy for user traffic.
- TLS or private network encryption between services in production.
- mTLS for remote sensors where feasible.
- Automated certificate renewal in production.

## Audit Logging

Audit events must include:

- Authentication success/failure.
- User, role, and group changes.
- API key creation, rotation, revocation.
- Dashboard filter save/update/delete.
- Raw event export.
- CTI connector configuration changes.
- Correlation status changes.
- False-positive decisions.
- Analyst notes and case updates.
- Admin access to sensitive credentials or raw payloads.

Each audit record should include actor, action, target type, target ID, timestamp, source IP, user agent, request ID, before/after JSON where relevant, and result.

## Reverse Proxy Protection

- Enforce HTTPS.
- Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- Rate limit authentication, search, export, and live-feed endpoints.
- Limit request body size.
- Restrict admin routes by source network where possible.

## Secrets

Development:

- Docker Compose `.env` for non-sensitive defaults.
- Docker secrets for passwords and tokens.

Production:

- Vault or SOPS-managed encrypted secrets.
- Per-service credentials.
- Rotation schedule for database passwords, API keys, connector tokens, and signing keys.

## Monitoring and Detection

Monitor:

- Ingestion lag.
- Broker topic lag.
- Worker failures and dead-letter topics.
- API latency and error rate.
- WebSocket connection count.
- PostgreSQL slow queries, locks, disk, WAL.
- OpenSearch cluster health and rejected queries.
- Neo4j heap, page cache, query latency.
- Keycloak login failures and MFA bypass attempts.
- Unauthorized access attempts and privilege changes.

## Backup and Recovery

- PostgreSQL: daily full backup, WAL archiving, restore test monthly.
- Neo4j: scheduled dumps and export of high-value graph entities.
- OpenSearch: snapshot repositories and index lifecycle policies.
- Keycloak: database backup plus exported realm configuration.
- Configuration: version-controlled Compose/Kubernetes manifests, SOPS/Vault metadata, documented restore order.
