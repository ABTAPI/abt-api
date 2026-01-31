
-- audit.sql
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  ts timestamptz NOT NULL,
  sub text,
  scopes text,
  endpoint text NOT NULL,
  case_id text NOT NULL,
  status text NOT NULL,
  input_hash char(64) NOT NULL,
  response_checksum char(32) NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events(ts);
CREATE INDEX IF NOT EXISTS audit_events_case_idx ON audit_events(case_id);
