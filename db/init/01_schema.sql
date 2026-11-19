-- Schema for the Echo security scanner.
-- Runs automatically on first start of an empty Postgres data volume.

CREATE TABLE IF NOT EXISTS images (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    tag           VARCHAR(128) NOT NULL,
    last_scan_at  TIMESTAMPTZ,
    scan_status   VARCHAR(16)  NOT NULL DEFAULT 'PENDING'
                  CHECK (scan_status IN ('PENDING', 'SCANNING', 'SUCCESS', 'FAILED')),
    last_error    TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_images_name_tag UNIQUE (name, tag)
);

CREATE TABLE IF NOT EXISTS cves (
    id           VARCHAR(64) PRIMARY KEY,            -- e.g. CVE-2021-23017
    title        TEXT,
    description  TEXT,
    primary_url  TEXT,
    source       VARCHAR(32) NOT NULL                -- scanner that reported it, e.g. trivy
);

CREATE TABLE IF NOT EXISTS packages (
    id    SERIAL PRIMARY KEY,
    name  VARCHAR(255) NOT NULL,
    type  VARCHAR(64)  NOT NULL DEFAULT 'unknown',   -- deb, apk, npm, python-pkg, ...
    CONSTRAINT uq_packages_name_type UNIQUE (name, type)
);

-- Relationship between images and CVEs, with the affected package details.
-- Severity lives here, not on cves: scanners rate a CVE per distribution/package source
-- (Trivy prefers vendor severity, e.g. the same CVE is MEDIUM on Debian and HIGH on Oracle Linux).
CREATE TABLE IF NOT EXISTS image_cves (
    id                 SERIAL PRIMARY KEY,
    image_id           INTEGER     NOT NULL REFERENCES images(id)   ON DELETE CASCADE,
    cve_id             VARCHAR(64) NOT NULL REFERENCES cves(id)     ON DELETE CASCADE,
    package_id         INTEGER     NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    installed_version  VARCHAR(255) NOT NULL,
    fixed_version      VARCHAR(255),
    -- 0=UNKNOWN 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL (Trivy's numeric mapping; higher is more severe)
    severity           SMALLINT    NOT NULL CHECK (severity BETWEEN 0 AND 4),
    detected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_image_cve_package UNIQUE (image_id, cve_id, package_id, installed_version)
);

CREATE INDEX IF NOT EXISTS ix_image_cves_image_id ON image_cves (image_id);
CREATE INDEX IF NOT EXISTS ix_image_cves_cve_id   ON image_cves (cve_id);
CREATE INDEX IF NOT EXISTS ix_image_cves_severity ON image_cves (severity);
