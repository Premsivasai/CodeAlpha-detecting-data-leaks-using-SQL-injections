# SecureShield - Enterprise SQL Injection Detection Platform

## Architecture Report v2.0

---

## 1. System Overview

SecureShield is an enterprise-grade, cloud-native SQL injection detection and data leak prevention platform. It provides multi-layer security with AI-powered threat detection, real-time monitoring, and comprehensive audit capabilities.

### 1.1 Technology Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Recharts, Tailwind CSS |
| Backend | FastAPI, Python 3.11+, SQLAlchemy async |
| Database | PostgreSQL 15, Redis 7 |
| AI/ML | Scikit-learn, TensorFlow, PyTorch, Transformers |
| Encryption | AES-256-EAX, PBKDF2 |
| Deployment | Docker, Kubernetes, Terraform |

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND LAYER                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   React     │ │  Recharts   │ │   WebSocket │ │   Context   │          │
│  │   SPA       │ │   Charts    │ │   Client    │ │    API      │          │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API GATEWAY LAYER                              │
│  ┌─────────────────────────────────────────────────────────────────┐        │
│  │                    FastAPI Application                          │        │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │        │
│  │  │   JWT      │  │    Rate     │  │  Security   │              │        │
│  │  │  Auth      │  │   Limiter   │  │  Headers    │              │        │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │        │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │        │
│  │  │  IP Block   │  │   MFA       │  │  CORS      │              │        │
│  │  │  Middleware │  │  Middleware │  │  Middleware│              │        │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │        │
│  └─────────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Detection Layer │   │   AI/ML Layer    │   │   Auth Layer     │
│  ┌─────────────┐  │   │  ┌─────────────┐ │   │  ┌─────────────┐ │
│  │    Regex    │  │   │  │  AI Query   │ │   │  │   JWT       │ │
│  │   Detector  │  │   │  │   Detector  │ │   │  │  Auth       │ │
│  └─────────────┘  │   │  └─────────────┘ │   │  └─────────────┘ │
│  ┌─────────────┐  │   │  ┌─────────────┐ │   │  ┌─────────────┐ │
│  │  Pattern    │  │   │  │    ML       │ │   │  │  Capability │ │
│  │  Matching  │  │   │  │  Classifier │ │   │  │   Manager   │ │
│  └─────────────┘  │   │  └─────────────┘ │   │  └─────────────┘ │
│  ┌─────────────┐  │   │  ┌─────────────┐ │   │  ┌─────────────┐ │
│  │  Behavior  │  │   │  │  Transformer│ │   │  │   RBAC      │ │
│  │  Analysis  │  │   │  │   Model     │ │   │  │   Checker   │ │
│  └─────────────┘  │   │  └─────────────┘ │   │  └─────────────┘ │
└──────────────────┘   └──────────────────┘   └──────────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CORE SERVICES LAYER                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │  Log Service    │  │  Alert Service  │  │  IP Blocker     │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Encryption    │  │  Notification  │  │  Incidents      │            │
│  │   Service       │  │   Service       │  │   Service       │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│   PostgreSQL     │   │     Redis        │   │   AI Models      │
│   Database       │   │   Cache/Pub/Sub  │   │   Storage        │
└──────────────────┘   └──────────────────┘   └──────────────────┘

---

## 3. Module Architecture

### 3.1 Authentication System (app/auth/)

```
AuthService
├── register_user()        - Create new user with encrypted email
├── authenticate_user()    - Verify credentials, track failed attempts
├── create_tokens()        - Generate JWT access + refresh tokens
├── cleanup_expired_tokens() - Remove expired refresh tokens

Security:
- bcrypt password hashing
- JWT with HS256
- Refresh token rotation
- TOTP MFA support
```

### 3.2 SQL Injection Detection (app/detection/)

```
SQLInjectionDetector
├── detect(query) → DetectionResult
│   ├── _detect_patterns()    - Regex pattern matching
│   ├── _detect_keywords()     - SQL keyword analysis
│   ├── _detect_entropy()      - Entropy analysis
│   └── _detect_encoding()     - URL encoding detection
│
├── Attack Types:
│   - UNION_BASED, BOOLEAN_BASED, ERROR_BASED
│   - TIME_BASED, BLIND_SQL, STACKED_QUERY
│   - TAUTOLOGY, PIGGY_BACKED, COMMENT_INJECTION
│
└── Severity Levels: CRITICAL, HIGH, MEDIUM, LOW
```

### 3.3 AI Detection System (app/ai_detection/)

```
AIQueryDetector
├── extract_features()
│   ├── keyword_density, special_char_ratio
│   ├── query_length, entropy
│   ├── union_count, comment_detection
│   └── parenthesis_depth, numeric_literal_count
│
├── _calculate_threat_score() - Weighted feature scoring
└── predict() → AIDetectionResult

MLPayloadClassifier
├── TfidfVectorizer (5000 features, 1-3 ngrams)
├── RandomForestClassifier (100 trees, depth 20)
└── train/predict/save/load methods
```

### 3.4 Encryption Service (app/encryption/)

```
AES256Encryption
├── encrypt() - AES-256-EAX mode with PBKDF2
├── decrypt() - Verify tag, decrypt
├── encrypt_dict() - Selective field encryption
├── hash_password() - PBKDF2-SHA256
└── generate_token() - Secure random tokens

KeyManager
├── rotate_key() - Key rotation with counter
└── get_current_key() - Current key retrieval
```

### 3.5 Capability System (app/capability/)

```
CapabilityManager
├── generate_capability() - Create encrypted capability tokens
├── validate_capability() - Verify permissions/resources
├── revoke_capability() - Single token revocation
├── revoke_all_user_capabilities() - Bulk revocation
├── get_user_capabilities() - List active capabilities
└── cleanup_expired() - Remove expired tokens

PermissionChecker
├── ROLE_PERMISSIONS - Role-based permission definitions
├── ROLE_RESOURCES - Resource access mappings
├── has_permission() - Permission validation
└── has_resource_access() - Resource access validation
```

### 3.6 Logging & Monitoring (app/logs/)

```
LogService
├── log_attack() - Record attack with WebSocket broadcast
├── log_query() - Log database queries
├── log_encryption() - Track encryption operations
├── log_failed_login() - Track failed auth attempts
├── log_audit() - Audit trail for compliance
├── get_attack_logs() - Queryable attack history
└── correlate_incident() - Auto-create incidents

AlertService
├── create_alert() - Generate security alerts
├── _notify_admins() - Alert admin users
├── get_active_alerts() - Query active alerts
└── resolve_alert() - Mark alert as resolved

IPBlocker
├── block_ip() - Add IP to blocklist with Redis cache
├── is_blocked() - Check IP status (with cache)
└── unblock_ip() - Remove from blocklist
```

---

## 4. Database Schema

### Core Tables

| Table | Purpose |
|-------|---------|
| users | User accounts with roles, MFA, encrypted emails |
| refresh_tokens | JWT refresh tokens with expiration |
| active_sessions | Active user sessions |
| capability_tokens | Capability-based access tokens |
| attack_logs | SQL injection attack records |
| query_logs | Database query logs |
| encryption_logs | Encryption operation audit |
| failed_login_attempts | Brute force tracking |
| ai_detection_results | AI model predictions |
| blocked_ips | IP blocklist |
| system_alerts | Security alerts |
| audit_logs | System audit trail |
| notifications | User notifications |
| incidents | Incident management |
| security_metrics | Metrics storage |

---

## 5. API Endpoints

### Authentication
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/mfa/setup` - MFA setup
- `POST /api/v1/auth/mfa/verify` - MFA verification
- `POST /api/v1/auth/logout` - Logout

### Detection
- `POST /api/v1/detection/analyze` - SQL injection detection
- `POST /api/v1/detection/ai-analyze` - AI-powered analysis

### Security
- `GET /api/v1/security/stats` - Security statistics
- `GET /api/v1/logs/attacks` - Attack logs
- `GET /api/v1/alerts` - System alerts
- `POST /api/v1/ip/block` - Block IP
- `POST /api/v1/ip/unblock` - Unblock IP

### Incidents
- `POST /api/v1/incidents` - Create incident
- `GET /api/v1/incidents` - List incidents
- `GET /api/v1/incidents/{id}` - Incident details
- `POST /api/v1/incidents/{id}/resolve` - Resolve incident

### Capabilities
- `POST /api/v1/capability/generate` - Generate token
- `GET /api/v1/capability/list` - List tokens

### WebSocket
- `WS /api/v1/ws/attacks` - Real-time attack feed

---

## 6. Security Features

### Multi-Layer Protection
1. **Input Validation** - Schema validation on all endpoints
2. **Pattern Detection** - Regex-based attack pattern matching
3. **AI Analysis** - ML-based threat scoring
4. **Rate Limiting** - Redis-backed per-IP rate limiting
5. **IP Blocking** - Automatic and manual IP blocking
6. **Encryption** - AES-256-EAX for sensitive data

### Authentication
- JWT with short-lived access tokens
- Refresh token rotation
- Optional MFA (TOTP)
- Capability-based access tokens

### Middleware Stack
1. CORS (outermost)
2. Request Logging
3. IP Blocking
4. Rate Limiting
5. Security Headers
6. GZip Compression

---

## 7. Deployment Architecture

### Development
```
localhost:3000 → Frontend (nginx)
localhost:8000 → Backend (FastAPI)
localhost:5432 → PostgreSQL
localhost:6379 → Redis
```

### Production (Kubernetes)
```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│   Frontend    │     │   Backend     │     │   Worker       │
│   (Deployment)│     │  (Deployment) │     │  (Deployment)  │
└────────────────┘     └────────────────┘     └────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────┐
│                      Services & Ingress                        │
└────────────────────────────────────────────────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│  PostgreSQL    │   │    Redis       │   │   MinIO/S3     │
│  (Cloud SQL)   │   │  (MemoryStore) │   │   (Storage)    │
└────────────────┘   └────────────────┘   └────────────────┘
```

---

## 8. Scalability Considerations

### Horizontal Scaling
- Backend stateless design
- Redis for session/capability sharing
- WebSocket connection handling
- Database connection pooling

### Performance Optimizations
- Redis caching for stats (15s TTL)
- Materialized views for hourly stats
- Async database operations
- Batch AI inference support
- CDN for frontend assets

### High Availability
- Kubernetes readiness/liveness probes
- Graceful shutdown handling
- Health check endpoints
- Automated material view refresh

---

## 9. Monitoring & Observability

### Metrics
- Request latency histogram
- Attack detection rates
- AI model confidence scores
- Database connection pool usage
- Redis memory usage

### Logging
- Structured JSON logging
- Request/response correlation
- Audit trail for compliance
- Attack payload logging (sanitized)

### Alerts
- High severity alerts → Admin notification
- Incident creation from repeated attacks
- Real-time WebSocket broadcast

---

## 10. Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DATABASE_URL | PostgreSQL connection | postgresql+asyncpg://... |
| REDIS_URL | Redis connection | redis://localhost:6379/0 |
| SECRET_KEY | JWT signing key | auto-generated |
| ENCRYPTION_KEY | AES encryption key | 32-byte hex |
| LOG_LEVEL | Logging level | INFO |
| RATE_LIMIT_PER_MINUTE | Rate limit | 60 |

---

## 11. Future Enhancements

### Planned Features
- Multi-tenant SaaS support
- Advanced LSTM/Transformer models
- Threat intelligence feeds (AlienVault OTX, VirusTotal)
- Database connectors (MySQL, MongoDB)
- Terraform cloud deployment
- SIEM integration
- Blockchain audit logs

### Roadmap
1. v2.0 - Multi-tenant architecture
2. v2.1 - Advanced AI models
3. v2.2 - Threat intelligence
4. v2.3 - Cloud deployment automation
5. v2.4 - Enterprise features (SIEM, blockchain)

---

*Document Version: 2.0*
*Last Updated: 2026*
*Author: SecureShield Architecture Team*