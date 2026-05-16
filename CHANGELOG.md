# Changelog

## Unreleased (2026-05-16)

- fix: stabilize SQL injection detection
  - Added case-insensitive matching for stacked queries to correctly detect patterns like `; DROP TABLE`.
  - Prefer TAUTOLOGY patterns when mapping to attack types.
  - Adjusted AI detector scoring: skip non-numeric features, increased pattern scoring influence, lowered `suspicious` threshold to 0.3.
  - Fixed aggregation logic so overall detection is `malicious` only when individual detectors report malicious.

- test: backend test suite now passing (28 passed, 0 failed)

Files changed (high level):
- `backend/app/detection/__init__.py`
- `backend/app/ai_detection/__init__.py`
- `backend/tests/*` (new/updated tests around detection, pubsub, notifications)

Notes:
- Branch: `fix/detection-tests` (local). Push to remote repository and open a PR when ready.
