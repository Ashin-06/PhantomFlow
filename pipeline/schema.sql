-- pipeline/schema.sql
-- Run once on fresh database: psql -f schema.sql

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- Encrypt sensitive columns

-- ===== FLOWS TABLE =====
CREATE TABLE flows (
    flow_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp       TIMESTAMPTZ NOT NULL,
    src_ip          INET NOT NULL,
    dst_ip          INET NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    sni             TEXT,
    ja3_hash        CHAR(32),
    ja4_hash        VARCHAR(64),
    duration_s      FLOAT,
    orig_bytes      BIGINT,
    resp_bytes      BIGINT,
    bytes_ratio     FLOAT,
    
    -- Timing features
    iat_mean_ms     FLOAT,
    iat_cv          FLOAT,
    periodicity_score FLOAT,
    dominant_period_ms FLOAT,
    
    -- DNS features
    dns_query       TEXT,
    dns_entropy     FLOAT,
    
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ===== ALERTS TABLE =====
CREATE TABLE alerts (
    alert_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    flow_id         UUID REFERENCES flows(flow_id),
    timestamp       TIMESTAMPTZ NOT NULL,
    
    threat_type     VARCHAR(50) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    confidence      FLOAT NOT NULL,
    
    -- Sub-scores from each model
    beacon_prob     FLOAT,
    dns_tunnel_prob FLOAT,
    exfil_score     FLOAT,
    
    -- Explanation (JSON column — stores full SHAP dict)
    shap_values     JSONB,
    explanation     TEXT,
    
    -- MITRE ATT&CK
    mitre_ttps      TEXT[],
    
    -- Analyst workflow
    analyst_status  VARCHAR(20) DEFAULT 'unreviewed'
                    CHECK (analyst_status IN (
                        'unreviewed', 'confirmed_tp', 'false_positive',
                        'escalated', 'suppressed'
                    )),
    analyst_id      VARCHAR(100),
    analyst_notes   TEXT,
    reviewed_at     TIMESTAMPTZ,
    
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ===== ACTIVE RESPONSE AUDIT LOG =====
CREATE TABLE response_audit (
    audit_id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id        UUID REFERENCES alerts(alert_id),
    action          VARCHAR(50) NOT NULL,
    target_ip       INET,
    target_domain   TEXT,
    approved_by     VARCHAR(100),  -- "SYSTEM_AUTO" or analyst username
    approved_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    executed_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      VARCHAR(100),
    status          VARCHAR(20) DEFAULT 'pending'
                    CHECK (status IN ('pending', 'executed', 'revoked', 'expired', 'failed')),
    error_detail    TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ===== ANALYST FEEDBACK (closes the retraining loop) =====
CREATE TABLE analyst_reviews (
    review_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id        UUID REFERENCES alerts(alert_id),
    flow_id         UUID REFERENCES flows(flow_id),
    analyst_id      VARCHAR(100) NOT NULL,
    analyst_label   INTEGER NOT NULL  -- 0=benign, 1=c2, 2=dns_tunnel, 3=exfil
                    CHECK (analyst_label BETWEEN 0 AND 3),
    analyst_notes   TEXT,
    confidence_override FLOAT,
    reviewed_at     TIMESTAMPTZ DEFAULT NOW()
);

-- ===== SUPPRESSION RULES =====
CREATE TABLE suppression_rules (
    rule_id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    
    -- Match criteria (NULL = match anything)
    src_ip_cidr     CIDR,
    dst_ip_cidr     CIDR,
    dst_port        INTEGER,
    sni_pattern     TEXT,       -- Regex pattern
    threat_type     VARCHAR(50),
    
    -- Valid for
    created_by      VARCHAR(100) NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,         -- NULL = never expires
    is_active       BOOLEAN DEFAULT TRUE,
    
    -- Why it exists (required for compliance)
    justification   TEXT NOT NULL,
    ticket_reference VARCHAR(50)         -- JIRA ticket, change request ID
);

-- ===== SENSOR REGISTRY =====
CREATE TABLE sensors (
    sensor_id       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname        VARCHAR(200) NOT NULL,
    interface       VARCHAR(50) NOT NULL,
    location        VARCHAR(200),        -- "DC-East Rack 12" etc.
    network_segment VARCHAR(100),
    
    -- Health
    last_heartbeat  TIMESTAMPTZ,
    flows_per_sec   FLOAT,
    packet_loss_pct FLOAT,
    
    -- Config
    model_version   VARCHAR(50),
    config_hash     VARCHAR(64),         -- Detect config drift
    
    is_active       BOOLEAN DEFAULT TRUE,
    registered_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ===== INDEXES =====
CREATE INDEX idx_alerts_timestamp    ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_threat_type  ON alerts(threat_type);
CREATE INDEX idx_alerts_severity     ON alerts(severity);
CREATE INDEX idx_alerts_status       ON alerts(analyst_status);
CREATE INDEX idx_flows_src_ip        ON flows(src_ip);
CREATE INDEX idx_flows_dst_ip        ON flows(dst_ip);
CREATE INDEX idx_flows_timestamp     ON flows(timestamp DESC);
CREATE INDEX idx_alerts_shap         ON alerts USING GIN(shap_values); -- JSON search
CREATE INDEX idx_flows_ja3            ON flows(ja3_hash) WHERE ja3_hash IS NOT NULL;

-- ===== ROW-LEVEL SECURITY =====
-- Tier1 analysts can only see alerts, not raw flows
ALTER TABLE flows ENABLE ROW LEVEL SECURITY;
-- Note: 'analyst_permissions' table should be created or mocked for this policy
-- CREATE POLICY tier1_no_raw_flows ON flows
--     USING (current_user IN (
--         SELECT username FROM analyst_permissions WHERE role = 'tier3'
--     ));
