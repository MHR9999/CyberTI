// Neo4j graph model for Custom Threat Intelligence & Honeypot Analytics Platform.
// Run in Neo4j Browser or cypher-shell.

CREATE CONSTRAINT ip_address_value IF NOT EXISTS
FOR (n:IPAddress) REQUIRE n.value IS UNIQUE;

CREATE CONSTRAINT asn_number IF NOT EXISTS
FOR (n:ASN) REQUIRE n.number IS UNIQUE;

CREATE CONSTRAINT country_iso IF NOT EXISTS
FOR (n:Country) REQUIRE n.iso_code IS UNIQUE;

CREATE CONSTRAINT honeypot_id IF NOT EXISTS
FOR (n:Honeypot) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT port_key IF NOT EXISTS
FOR (n:Port) REQUIRE (n.number, n.transport) IS UNIQUE;

CREATE CONSTRAINT protocol_name IF NOT EXISTS
FOR (n:Protocol) REQUIRE n.name IS UNIQUE;

CREATE CONSTRAINT username_value IF NOT EXISTS
FOR (n:Username) REQUIRE n.value IS UNIQUE;

CREATE CONSTRAINT password_hash IF NOT EXISTS
FOR (n:Password) REQUIRE n.hash IS UNIQUE;

CREATE CONSTRAINT malware_name IF NOT EXISTS
FOR (n:Malware) REQUIRE n.name IS UNIQUE;

CREATE CONSTRAINT file_hash_value IF NOT EXISTS
FOR (n:FileHash) REQUIRE (n.algorithm, n.value) IS UNIQUE;

CREATE CONSTRAINT cve_id IF NOT EXISTS
FOR (n:CVE) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT suricata_signature_sid IF NOT EXISTS
FOR (n:SuricataSignature) REQUIRE n.sid IS UNIQUE;

CREATE CONSTRAINT campaign_name IF NOT EXISTS
FOR (n:AttackCampaign) REQUIRE n.name IS UNIQUE;

CREATE CONSTRAINT threat_actor_name IF NOT EXISTS
FOR (n:ThreatActor) REQUIRE n.name IS UNIQUE;

CREATE CONSTRAINT indicator_key IF NOT EXISTS
FOR (n:Indicator) REQUIRE (n.type, n.value) IS UNIQUE;

CREATE CONSTRAINT malware_family_name IF NOT EXISTS
FOR (n:MalwareFamily) REQUIRE n.name IS UNIQUE;

CREATE CONSTRAINT tactic_id IF NOT EXISTS
FOR (n:Tactic) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT technique_id IF NOT EXISTS
FOR (n:Technique) REQUIRE n.id IS UNIQUE;

CREATE INDEX attack_event_observed_at IF NOT EXISTS
FOR (n:AttackEvent) ON (n.observed_at);

CREATE INDEX ip_reputation_score IF NOT EXISTS
FOR (n:IPAddress) ON (n.reputation_score);

// Example node labels:
// (:IPAddress {value, first_seen, last_seen, reputation_category, reputation_score})
// (:ASN {number, name, organization})
// (:Country {iso_code, name, latitude, longitude})
// (:Honeypot {id, sensor_id, name, type})
// (:Port {number, transport, service_name})
// (:Protocol {name, transport})
// (:Username {value})
// (:Password {hash, masked_value})
// (:Malware {name})
// (:FileHash {algorithm, value})
// (:CVE {id, severity, cvss_score})
// (:SuricataSignature {sid, signature, category, severity})
// (:AttackCampaign {name, first_seen, last_seen})
// (:ThreatActor {name, confidence})
// (:Indicator {type, value, source, confidence})
// (:MalwareFamily {name})
// (:Tactic {id, name})
// (:Technique {id, name})

// Required relationship types:
// (:IPAddress)-[:IP_ATTACKED_HONEYPOT {count, first_seen, last_seen}]->(:Honeypot)
// (:IPAddress)-[:IP_USED_PORT {count, first_seen, last_seen}]->(:Port)
// (:IPAddress)-[:IP_FROM_COUNTRY]->(:Country)
// (:IPAddress)-[:IP_BELONGS_TO_ASN]->(:ASN)
// (:IPAddress)-[:IP_TRIGGERED_SIGNATURE {count, first_seen, last_seen}]->(:SuricataSignature)
// (:IPAddress)-[:IP_LINKED_TO_CVE {confidence, source}]->(:CVE)
// (:IPAddress)-[:IP_USED_USERNAME {count, first_seen, last_seen}]->(:Username)
// (:IPAddress)-[:IP_USED_PASSWORD {count, first_seen, last_seen}]->(:Password)
// (:IPAddress)-[:IP_DOWNLOADED_FILE {url, first_seen, last_seen}]->(:FileHash)
// (:FileHash)-[:FILE_HAS_HASH]->(:FileHash)
// (:CVE)-[:CVE_EXPLOITED_SERVICE]->(:Port)
// (:Indicator)-[:INDICATOR_RELATED_TO_THREAT_ACTOR {confidence, source}]->(:ThreatActor)
// (:ThreatActor)-[:THREAT_ACTOR_USES_MALWARE {confidence, source}]->(:Malware)
// (:AttackCampaign)-[:ATTACK_USES_TECHNIQUE {confidence, source}]->(:Technique)

// Parameterized upsert pattern for an enriched honeypot event:
//
// MERGE (ip:IPAddress {value: $src_ip})
// SET ip.last_seen = datetime($observed_at),
//     ip.first_seen = coalesce(ip.first_seen, datetime($observed_at)),
//     ip.reputation_category = $reputation_category,
//     ip.reputation_score = $reputation_score
// MERGE (country:Country {iso_code: $country_iso})
// SET country.name = $country_name
// MERGE (asn:ASN {number: $asn_number})
// SET asn.name = $asn_name,
//     asn.organization = $asn_org
// MERGE (hp:Honeypot {id: $honeypot_id})
// SET hp.sensor_id = $sensor_id,
//     hp.name = $honeypot_name,
//     hp.type = $honeypot_type
// MERGE (port:Port {number: $dst_port, transport: $transport})
// SET port.service_name = $service_name
// MERGE (protocol:Protocol {name: $protocol})
// MERGE (ip)-[:IP_FROM_COUNTRY]->(country)
// MERGE (ip)-[:IP_BELONGS_TO_ASN]->(asn)
// MERGE (ip)-[attacked:IP_ATTACKED_HONEYPOT]->(hp)
// SET attacked.count = coalesce(attacked.count, 0) + 1,
//     attacked.last_seen = datetime($observed_at),
//     attacked.first_seen = coalesce(attacked.first_seen, datetime($observed_at))
// MERGE (ip)-[used_port:IP_USED_PORT]->(port)
// SET used_port.count = coalesce(used_port.count, 0) + 1,
//     used_port.last_seen = datetime($observed_at),
//     used_port.first_seen = coalesce(used_port.first_seen, datetime($observed_at))
// MERGE (port)-[:USES_PROTOCOL]->(protocol);
//
// Optional credential relationship:
//
// MERGE (username:Username {value: $username})
// MERGE (ip)-[used_username:IP_USED_USERNAME]->(username)
// SET used_username.count = coalesce(used_username.count, 0) + 1,
//     used_username.last_seen = datetime($observed_at),
//     used_username.first_seen = coalesce(used_username.first_seen, datetime($observed_at));
//
// Optional CTI correlation:
//
// MERGE (indicator:Indicator {type: $indicator_type, value: $indicator_value})
// SET indicator.source = $indicator_source,
//     indicator.confidence = $indicator_confidence,
//     indicator.last_seen = datetime($observed_at)
// MERGE (ip)-[matches:IP_MATCHED_INDICATOR]->(indicator)
// SET matches.confidence = $match_confidence,
//     matches.source = $indicator_source,
//     matches.last_seen = datetime($observed_at);
