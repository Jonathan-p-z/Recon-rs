-- A single scan run against one target domain.
CREATE TABLE scans (
    id UUID PRIMARY KEY,
    target_domain TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    candidates_tested INTEGER
);
