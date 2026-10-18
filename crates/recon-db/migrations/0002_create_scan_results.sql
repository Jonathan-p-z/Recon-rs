-- One probed/resolved subdomain result belonging to a scan run.
CREATE TABLE scan_results (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    ip TEXT,
    cname TEXT,
    http_status INTEGER,
    title TEXT,
    priority TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_results_scan_id_subdomain ON scan_results (scan_id, subdomain);
