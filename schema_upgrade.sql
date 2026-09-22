USE ztna_gateway;

CREATE TABLE IF NOT EXISTS identity_risk (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    failed_login_risk INT NOT NULL DEFAULT 0,
    behavior_risk INT NOT NULL DEFAULT 0,
    total_risk INT NOT NULL DEFAULT 0,
    reason VARCHAR(255),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_risk (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(50) NOT NULL UNIQUE,
    risk_score INT NOT NULL DEFAULT 0,
    threat_level VARCHAR(30) DEFAULT 'Low',
    last_attack_type VARCHAR(100),
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
);

-- Run these ALTER statements only if the columns do not already exist.
-- Check first with: DESCRIBE access_sessions;
-- ALTER TABLE access_sessions ADD COLUMN mfa_verified TINYINT NOT NULL DEFAULT 0;
-- ALTER TABLE access_sessions ADD COLUMN certificate_verified TINYINT NOT NULL DEFAULT 0;
-- ALTER TABLE access_sessions ADD COLUMN auth_level VARCHAR(50) DEFAULT 'BASIC';
