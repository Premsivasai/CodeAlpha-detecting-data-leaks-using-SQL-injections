# High-Impact Designs for SecureShield

This document provides focused, high-impact architecture and design proposals to move SecureShield from a demonstration prototype to a production-ready, scalable, and secure service. Each section includes goals, constraints, proposed design, required components, data models, API sketches, sequence diagrams (textual), and migration steps.

---

## 1. Materialized View Refreshing & Cache Invalidation (High Impact)

Goal: Keep dashboard aggregates up-to-date with minimal DB load and near real-time freshness.

Why: The dashboard relies on aggregated hourly statistics; recomputing these on-demand is expensive and causes latency at scale.

Design Summary:
- Use a scheduled refresh for the materialized view `hourly_attack_stats` and a publish/subscribe invalidation method using Redis for near real-time updates.

Components:
- `APScheduler` (in-process scheduler) or `Celery Beat` (distributed schedule) to run hourly REFRESH.
- Redis Pub/Sub channel `cache:security:invalidate` for invalidation messages.
- On new attack ingestion, publish to `cache:security:invalidate` and increment a short-lived counter for fine-grained invalidation.

Data Flow:
1. New attack inserted into `attack_logs`.
2. `log_service.log_attack()` publishes a message to Redis channel with attack metadata.
3. Backend API servers subscribe to the channel; on message, they invalidate local in-memory caches and evict Redis `security:stats:24h` key.
4. APScheduler runs hourly `REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_attack_stats` to keep aggregates consistent.

Edge Cases & Constraints:
- If multiple servers run, rely on Celery/Redis for distributed locks to avoid concurrent refreshes.
- Use `CONCURRENTLY` when supported to avoid blocking writes.

Migration Steps:
1. Add `APScheduler` job in `backend/main.py` to run hourly refresh.
2. Add Redis pub/sub listener and eviction logic in `main.py` subscription task.
3. Modify `log_service.log_attack()` to `publish()` invalidation messages after successful commit.
4. Adjust `get_security_stats()` to read from `hourly_attack_stats` when relevant.

---

## 2. WebSocket Scaling with Redis Pub/Sub (High Impact)

Goal: Support horizontal scaling of WebSocket clients across multiple backend instances.

Why: In-process WebSocket broadcasting doesn't scale to multiple processes or hosts.

Design Summary:
- Use Redis Pub/Sub as a channel layer. When `log_service` writes a new attack, publish to Redis channel `ws:attacks`. Each backend instance subscribes and forwards messages to connected WebSocket clients.

Components:
- `redis.asyncio` for pub/sub.
- `backend/main.py` to maintain subscribers and forward to local `active_websockets`.

Sequence:
1. `log_service.log_attack()` publishes `ws:attacks` with JSON payload.
2. All backend instances receive message from Redis and call `await ws.send_json()` for each connected client.

Edge Cases & Notes:
- Ensure message delivery is best-effort; clients may reconnect.
- Add small per-instance dedup detection if messages might be published multiple times.

---

## 3. Incident Correlation & Deduplication (High Impact)

Goal: Reduce alert noise by correlating multiple related attack logs into a single incident.

Design Summary:
- Implement an `incident_aggregation` service that groups `attack_logs` by attacker fingerprint (IP + signature) over a sliding window and creates or appends to incidents.

Key Concepts:
- Fingerprint = hash(ip_address + normalized_attack_signature)
- Sliding window = last 1 hour by default
- Thresholds: create incident after N events or when severity high/critical

Data Model Additions:
- `incident_events` table linking `attack_log_id` -> `incident_id` with event-level metadata
- `incident` `updated_at`, `status`, `event_count`

Process:
1. On `log_attack`, compute fingerprint and look for an open incident with same fingerprint.
2. If found, append event; increment `event_count`; update severity if needed.
3. If not found and threshold exceeded, create a new incident and create a system alert.

Implementation options:
- Synchronous on insert (simple) — acceptable for low throughput.
- Asynchronous via Celery queue for high throughput.

---

## 4. Reliable Notifications & Delivery (High Impact)

Goal: Ensure alerts and notifications are delivered reliably and can be retried.

Design Summary:
- Use a durable queue (Redis streams or RabbitMQ) for delivery jobs with acknowledgement and retry policy.
- Store notification records and delivery attempts in `notifications` and `notification_attempts` tables.

Delivery Flow:
1. Create notification record in DB.
2. Push delivery job to queue with payload and webhook URL(s).
3. Worker consumes job, attempts delivery, records attempt; on failure, reschedule with backoff.

Components:
- `Redis Streams` or `RabbitMQ` for job queue.
- Worker process (Celery or custom asyncio worker).

Observability:
- Expose metrics for queue length, success rate, and errors.

---

## 5. Model Serving & Feature Store (High Impact)

Goal: Improve AI detection maturity by capturing features, versioning models, and enabling offline retraining.

Design Summary:
- Store extracted features in `ai_detection_results.features` and a separate `features_store` table for training samples.
- Add `models` table to record model versions, training data references, and performance metrics.
- Expose a `model_inference` microservice for heavier models.

Flow:
1. On detection, extract features and persist them with label (if known).
2. Schedule batch training jobs that read `features_store` and produce new model artifacts.
3. Deploy new model and update `models` table with metadata.

---

## 6. HA, Backups, and Disaster Recovery (High Impact)

Goal: Protect production data and ensure quick recovery.

Key Items:
- Use managed Postgres with automated backups and PITR.
- Regularly test backup restoration in a staging environment.
- Store encrypted backups in durable object storage (S3/Azure Blob).

Backup Plan:
- Daily full backups + continuous WAL archiving (PITR window configurable).
- Snapshot rotation policy and retention compliant with data governance.

---

## 7. Authentication Hardening & Session Management (High Impact)

Goal: Improve token security, session revocation, and MFA enforcement.

Design Summary:
- Use `RefreshToken` table for revocation and active session tracking (already present).
- Add middleware to check `RefreshToken.revoked` on refresh and `ActiveSession` for token-based checks.
- Enforce MFA on sensitive endpoints and provide adaptive MFA (risk-based) later.

---

## 8. CI/CD & Testing Strategy (High Impact)

Goal: Ensure code quality and prevent regressions through automated tests and pipelines.

Recommended Pipeline Steps:
- Linting and static checks (mypy, bandit, black/isort)
- Unit tests (backend pytest; frontend jest)
- Integration tests with ephemeral Postgres (testcontainers) and Redis mocks
- E2E smoke tests (Playwright) for login → dashboard → ingest flow
- Build artifacts for frontend and backend container images

---

## 9. Observability & Runbooks (High Impact)

Goal: Provide SREs and analysts tools and runbooks to respond to incidents.

Observability:
- Add Prometheus metrics for request latency, db query timings, model inference time, detection rate.
- Structured logs with request IDs and correlation IDs.
- Traces (OpenTelemetry) for cross-service flow.

Runbooks:
- Create short runbooks for common incidents: high false-positive spike, DB overload, Redis failures, model degradation.
- Include remediation commands and escalation steps.

---

## Implementation Prioritization (2-week sprints)

Sprint 1 (1-2 weeks):
- Materialized view refresh + Redis invalidation
- Redis Pub/Sub WebSocket scaling
- Basic incident correlation (synchronous)

Sprint 2 (2-3 weeks):
- Notification delivery queue + retry worker
- Incident UI + link alerts to incidents
- Add backup & restore playbook

Sprint 3 (3-4 weeks):
- Model feature store and training pipeline scaffolding
- CI expansion: integration tests and E2E smoke tests
- Token/session hardening and MFA enforcement

---

If you want, I can now implement Sprint 1 tasks in the codebase (add APScheduler job, Redis pub/sub wiring, and synchronous incident correlation). Tell me which Sprint 1 subtask to start with and I'll add the code, tests, and documentation accordingly.
