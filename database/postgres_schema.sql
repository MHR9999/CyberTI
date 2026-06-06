-- PostgreSQL schema for Custom Threat Intelligence & Honeypot Analytics Platform.
-- Requires PostgreSQL 15+.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS threat_intel;
SET search_path TO threat_intel, public;

CREATE TABLE countries (
    id BIGSERIAL PRIMARY KEY,
    iso_code CHAR(2) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    region TEXT,
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE asn (
    id BIGSERIAL PRIMARY KEY,
    asn_number BIGINT NOT NULL UNIQUE,
    name TEXT,
    organization TEXT,
    route TEXT,
    country_id BIGINT REFERENCES countries(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE source_ips (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL UNIQUE,
    country_id BIGINT REFERENCES countries(id),
    asn_id BIGINT REFERENCES asn(id),
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    reputation_score INTEGER NOT NULL DEFAULT 0 CHECK (reputation_score BETWEEN 0 AND 100),
    reputation_category TEXT NOT NULL DEFAULT 'unknown',
    is_tor_exit_node BOOLEAN NOT NULL DEFAULT false,
    is_mass_scanner BOOLEAN NOT NULL DEFAULT false,
    is_bot BOOLEAN NOT NULL DEFAULT false,
    is_proxy_or_vpn BOOLEAN NOT NULL DEFAULT false,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE honeypots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id TEXT NOT NULL,
    name TEXT NOT NULL,
    honeypot_type TEXT NOT NULL,
    service_name TEXT,
    listen_ip INET,
    listen_port INTEGER CHECK (listen_port BETWEEN 0 AND 65535),
    location_name TEXT,
    country_id BIGINT REFERENCES countries(id),
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (sensor_id, name, honeypot_type)
);

CREATE TABLE destination_ports (
    id BIGSERIAL PRIMARY KEY,
    port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    transport TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    description TEXT,
    UNIQUE (port, transport)
);

CREATE TABLE protocols (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    transport TEXT,
    description TEXT
);

CREATE TABLE credentials (
    id BIGSERIAL PRIMARY KEY,
    username TEXT,
    password TEXT,
    username_hash TEXT,
    password_hash TEXT,
    credential_type TEXT NOT NULL DEFAULT 'observed',
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    observation_count BIGINT NOT NULL DEFAULT 0,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (username, password)
);

CREATE TABLE malware_downloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ip_id BIGINT REFERENCES source_ips(id),
    honeypot_id UUID REFERENCES honeypots(id),
    url TEXT,
    filename TEXT,
    mime_type TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    size_bytes BIGINT,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    storage_ref TEXT,
    raw_event JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cves (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL UNIQUE,
    description TEXT,
    cvss_score NUMERIC(3,1),
    severity TEXT,
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE suricata_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signature_id INTEGER,
    signature TEXT NOT NULL,
    category TEXT,
    severity INTEGER CHECK (severity BETWEEN 1 AND 5),
    rev INTEGER,
    gid INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (signature_id, signature)
);

CREATE TABLE suricata_alert_cves (
    suricata_alert_id UUID NOT NULL REFERENCES suricata_alerts(id) ON DELETE CASCADE,
    cve_id BIGINT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    PRIMARY KEY (suricata_alert_id, cve_id)
);

CREATE TABLE ip_reputation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_ip_id BIGINT NOT NULL REFERENCES source_ips(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    category TEXT NOT NULL,
    score INTEGER CHECK (score BETWEEN 0 AND 100),
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    is_known_attacker BOOLEAN NOT NULL DEFAULT false,
    is_tor_exit_node BOOLEAN NOT NULL DEFAULT false,
    is_mass_scanner BOOLEAN NOT NULL DEFAULT false,
    is_bot BOOLEAN NOT NULL DEFAULT false,
    is_proxy_or_vpn BOOLEAN NOT NULL DEFAULT false,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (source_ip_id, provider, observed_at)
);

CREATE TABLE attack_events (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    observed_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_system TEXT NOT NULL DEFAULT 'tpot',
    source_index TEXT,
    source_event_id TEXT,
    sensor_id TEXT,
    event_type TEXT NOT NULL,
    honeypot_id UUID REFERENCES honeypots(id),
    source_ip_id BIGINT REFERENCES source_ips(id),
    destination_port_id BIGINT REFERENCES destination_ports(id),
    protocol_id BIGINT REFERENCES protocols(id),
    credential_id BIGINT REFERENCES credentials(id),
    malware_download_id UUID REFERENCES malware_downloads(id),
    suricata_alert_id UUID REFERENCES suricata_alerts(id),
    src_ip INET,
    src_port INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip INET,
    dst_port INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    protocol TEXT,
    honeypot_type TEXT,
    username TEXT,
    password TEXT,
    p0f_os TEXT,
    cve_ids TEXT[] NOT NULL DEFAULT '{}',
    reputation_category TEXT NOT NULL DEFAULT 'unknown',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    tags TEXT[] NOT NULL DEFAULT '{}',
    raw_event JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, observed_at)
) PARTITION BY RANGE (observed_at);

CREATE TABLE attack_events_default PARTITION OF attack_events DEFAULT;

CREATE TABLE enrichment_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_event_id UUID NOT NULL,
    attack_event_observed_at TIMESTAMPTZ NOT NULL,
    source_ip_id BIGINT REFERENCES source_ips(id),
    enrichment_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    score INTEGER CHECK (score BETWEEN 0 AND 100),
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (attack_event_id, attack_event_observed_at)
        REFERENCES attack_events(id, observed_at) ON DELETE CASCADE
);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_subject TEXT NOT NULL UNIQUE,
    email CITEXT NOT NULL UNIQUE,
    display_name TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id UUID REFERENCES users(id),
    actor_type TEXT NOT NULL DEFAULT 'user',
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    source_ip INET,
    user_agent TEXT,
    request_id TEXT,
    result TEXT NOT NULL DEFAULT 'success',
    before_state JSONB,
    after_state JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE dashboard_filters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    is_shared BOOLEAN NOT NULL DEFAULT false,
    filter_config JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_user_id, name)
);

CREATE TABLE cti_objects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    object_type TEXT NOT NULL,
    name TEXT,
    description TEXT,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    labels TEXT[] NOT NULL DEFAULT '{}',
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    raw_object JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, external_id)
);

CREATE TABLE cti_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cti_object_id UUID NOT NULL REFERENCES cti_objects(id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    pattern TEXT,
    pattern_type TEXT,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (indicator_type, value, cti_object_id)
);

CREATE TABLE cti_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_cti_object_id UUID NOT NULL REFERENCES cti_objects(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    target_cti_object_id UUID NOT NULL REFERENCES cti_objects(id) ON DELETE CASCADE,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    start_time TIMESTAMPTZ,
    stop_time TIMESTAMPTZ,
    raw_relationship JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_cti_object_id, relationship_type, target_cti_object_id)
);

CREATE TABLE cti_sightings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cti_object_id UUID REFERENCES cti_objects(id) ON DELETE CASCADE,
    attack_event_id UUID,
    attack_event_observed_at TIMESTAMPTZ,
    source TEXT NOT NULL,
    sighted_at TIMESTAMPTZ NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    count INTEGER NOT NULL DEFAULT 1,
    raw_sighting JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (attack_event_id, attack_event_observed_at)
        REFERENCES attack_events(id, observed_at) ON DELETE SET NULL
);

CREATE TABLE correlation_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_event_id UUID,
    attack_event_observed_at TIMESTAMPTZ,
    source_ip_id BIGINT REFERENCES source_ips(id),
    cti_object_id UUID REFERENCES cti_objects(id),
    correlation_type TEXT NOT NULL,
    confidence INTEGER CHECK (confidence BETWEEN 0 AND 100),
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'new',
    explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
    assigned_to UUID REFERENCES users(id),
    reviewed_by UUID REFERENCES users(id),
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (attack_event_id, attack_event_observed_at)
        REFERENCES attack_events(id, observed_at) ON DELETE CASCADE
);

CREATE INDEX idx_attack_events_observed_at ON attack_events (observed_at DESC);
CREATE INDEX idx_attack_events_src_ip ON attack_events (src_ip);
CREATE INDEX idx_attack_events_dst_port ON attack_events (dst_port);
CREATE INDEX idx_attack_events_honeypot_type ON attack_events (honeypot_type);
CREATE INDEX idx_attack_events_reputation ON attack_events (reputation_category);
CREATE INDEX idx_attack_events_risk_score ON attack_events (risk_score DESC);
CREATE INDEX idx_attack_events_raw_event_gin ON attack_events USING GIN (raw_event);
CREATE INDEX idx_source_ips_country ON source_ips (country_id);
CREATE INDEX idx_source_ips_asn ON source_ips (asn_id);
CREATE INDEX idx_source_ips_reputation ON source_ips (reputation_category, reputation_score DESC);
CREATE INDEX idx_credentials_username ON credentials (username);
CREATE INDEX idx_credentials_password ON credentials (password);
CREATE INDEX idx_suricata_signature_id ON suricata_alerts (signature_id);
CREATE INDEX idx_cves_cve_id ON cves (cve_id);
CREATE INDEX idx_enrichment_type_provider ON enrichment_results (enrichment_type, provider);
CREATE INDEX idx_audit_logs_occurred_at ON audit_logs (occurred_at DESC);
CREATE INDEX idx_cti_objects_type ON cti_objects (object_type);
CREATE INDEX idx_cti_indicators_value ON cti_indicators (indicator_type, value);
CREATE INDEX idx_cti_relationships_type ON cti_relationships (relationship_type);
CREATE INDEX idx_correlation_status_score ON correlation_findings (status, risk_score DESC);

INSERT INTO roles (name, description, permissions)
VALUES
    ('Admin', 'Full platform administration', ARRAY['*']),
    ('SOC Analyst', 'Honeypot investigation and case workflow', ARRAY['dashboard:read','attack:read','case:write','note:write']),
    ('CTI Analyst', 'CTI analysis, correlation, and false-positive review', ARRAY['dashboard:read','attack:read','cti:read','cti:write','correlation:review']),
    ('Viewer', 'Read-only dashboard access with sensitive fields masked', ARRAY['dashboard:read']),
    ('Auditor', 'Audit and compliance review', ARRAY['audit:read','dashboard:read'])
ON CONFLICT (name) DO NOTHING;
