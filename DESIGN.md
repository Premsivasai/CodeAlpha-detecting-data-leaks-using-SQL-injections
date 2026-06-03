Design notes and immediate roadmap

Objectives:
- Move AI inference to separate service (batched, instrumented, model registry).
- Redis-backed rate limiting for distributed enforcement.
- Sandbox detection as a policy service used by all execution paths.
- Replay/audit storage: immutable logs, signed exports, read-only replay flows.

Immediate design decisions made in code:
- Rate limiting uses Redis when available, with an in-memory fallback.
- Replay endpoint implemented as simulation by default; admin opt-in required for actual re-execution.
- Role-based execution timeouts applied per-request.

Next steps:
- Implement Redis Lua script for atomic sliding window limits.
- Extract AI detection to an HTTP/gRPC inference service.
- Harden connectors to support transaction-level read-only execution for replays.
- Add E2E and load-testing pipelines targeting rate-limiter and replay flows.
