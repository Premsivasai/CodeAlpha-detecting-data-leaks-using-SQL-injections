-- Phase 1 DB optimizations: indexes and materialized view for analytics

-- Indexes for attack_logs
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_type ON attack_logs (attack_type);
CREATE INDEX IF NOT EXISTS idx_attack_logs_ip_address ON attack_logs (ip_address);

-- Materialized view for hourly attack counts
CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_attack_stats AS
SELECT date_trunc('hour', timestamp) AS hour,
       attack_type,
       severity,
       count(*) AS cnt
FROM attack_logs
GROUP BY hour, attack_type, severity;

-- Refresh command (run periodically e.g. via cron or scheduler)
-- REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_attack_stats;
