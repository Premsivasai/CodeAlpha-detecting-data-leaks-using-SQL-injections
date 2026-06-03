Operational notes

Redis
- Ensure a Redis instance is available and configured on app startup as `app.state.redis`.
- Use a dedicated Redis DB for rate-limiting and short-lived caches.

Secrets
- Store DB credentials in a secrets store (HashiCorp Vault, Azure Key Vault) and load them into `GlobalConfig` encrypted fields.

Deployment
- Run backend with Uvicorn+Gunicorn workers behind an ingress (Traefik/Kong); workers share Redis for coordination.
- Configure resource limits and liveness/readiness probes in Kubernetes manifests.

Local dev
- `docker-compose.yml` can include Redis and Postgres to mimic production. Ensure `app.state.redis` is set in `backend/main.py`.

Troubleshooting
- Rate limit errors: check Redis connectivity and `rate:*` keys.
- Replay failures: review `QueryLog` entries and `replay_failed` audit logs.
