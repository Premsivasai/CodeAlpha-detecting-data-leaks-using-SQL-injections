# SecureShield - SQL Injection Detection and Data Leak Prevention System

## Overview

SecureShield is a comprehensive cloud-based cybersecurity platform designed to detect and prevent SQL injection attacks, encrypt sensitive data using AES-256 encryption, and provide real-time security monitoring through a modern dashboard interface.

## Features

### Core Security Features
- **SQL Injection Detection Engine**: Multi-layer detection system using pattern matching, regex, behavior analysis, and AI/ML
- **AES-256 Encryption**: Enterprise-grade encryption for sensitive data including passwords, emails, and tokens
- **Capability-Based Access Control**: Fine-grained permissions with token-based authentication
- **Double-Layer Security Architecture**: ORM protection + encrypted storage for defense in depth
- **Real-Time Attack Monitoring**: Live feed with WebSocket updates and instant notifications

### AI-Powered Detection
- Machine learning model for threat scoring
- Query entropy analysis
- Pattern recognition
- Anomaly detection

### Monitoring & Analytics
- Security dashboard with real-time metrics
- Attack timeline visualization
- Threat heatmaps
- Security score tracking

### Authentication & Authorization
- JWT-based authentication
- Refresh token support
- Role-based access control (RBAC)
- Capability token system

## Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT with python-jose
- **Encryption**: PyCryptodome (AES-256)
- **AI/ML**: Scikit-learn, NumPy, Pandas

### Frontend
- **Framework**: React 18
- **Styling**: Custom CSS with modern dark theme
- **Charts**: Recharts
- **HTTP Client**: Axios

### Deployment
- Docker & Docker Compose
- Nginx reverse proxy

## Project Structure

```
secureshield/
├── backend/
│   ├── app/
│   │   ├── auth/          # Authentication system
│   │   ├── encryption/    # AES-256 encryption
│   │   ├── detection/     # SQL injection detection
│   │   ├── capability/   # Capability-based access control
│   │   ├── ai_detection/ # AI/ML detection
│   │   ├── logs/         # Logging system
│   │   ├── middleware/   # Security middleware
│   │   ├── models/       # Database models
│   │   ├── routes/       # API routes
│   │   └── config/       # Configuration
│   ├── main.py           # FastAPI application
│   ├── requirements.txt  # Python dependencies
│   └── Dockerfile        # Backend container
│
├── frontend/
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API services
│   │   ├── context/      # React context
│   │   └── styles/      # CSS styles
│   ├── public/
│   ├── package.json
│   ├── Dockerfile
│   └── nginx.conf
│
├── docker-compose.yml
└── README.md
```

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Node.js 18+ (for local frontend development)
- Python 3.11+ (for local backend development)

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd secureshield
```

2. Start all services:
```bash
docker-compose up -d
```

3. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/api/v1/docs

### Manual Setup

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows
pip install -r requirements.txt
uvicorn main:app --reload
```

#### Frontend
```bash
cd frontend
npm install
npm start
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `GET /api/v1/users/me` - Get current user

### Detection
- `POST /api/v1/detection/analyze` - Analyze query for SQL injection
- `POST /api/v1/detection/ai-analyze` - AI-powered query analysis

### Security
- `GET /api/v1/security/stats` - Get security statistics
- `GET /api/v1/logs/attacks` - Get attack logs
- `GET /api/v1/alerts` - Get security alerts
- `POST /api/v1/ip/block` - Block IP address
- `POST /api/v1/ip/unblock` - Unblock IP address

### Capabilities
- `POST /api/v1/capability/generate` - Generate capability token
- `GET /api/v1/capability/list` - List user capabilities

## Database Schema

### Key Tables
- `users` - User accounts with roles
- `attack_logs` - SQL injection attack records
- `capability_tokens` - Capability-based access tokens
- `system_alerts` - Security alerts
- `blocked_ips` - Blocked IP addresses
- `ai_detection_results` - AI model predictions
- `audit_logs` - System audit trail

## Security Architecture

### Layer 1: SQL Injection Prevention
- Prepared statements via SQLAlchemy ORM
- Pattern-based detection engine
- Regex detection for known attack patterns
- Behavior analysis and anomaly detection

### Layer 2: Encrypted Data Protection
- AES-256 EAX mode encryption
- Secure key management
- Encrypted storage for sensitive fields
- Data integrity validation

### Access Control
- JWT authentication tokens
- Capability-based permissions
- Role-based access control (RBAC)
- Least privilege enforcement

## Deployment

### Production Environment Variables

```bash
DATABASE_URL=postgresql://user:pass@host:5432/db
SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key
```

### Cloud Deployment

The application can be deployed to:
- **Render**: Using the Docker configuration
- **Railway**: Compatible with Docker Compose
- **AWS ECS**: Using the Dockerfile
- **Vercel**: Frontend only (requires separate backend)

## Testing

### Run Tests
```bash
cd backend
pytest tests/
```

### Security Testing
- Use OWASP ZAP for penetration testing
- Test with SQLMap for SQL injection validation
- Verify encryption with various payloads

## License

MIT License - See LICENSE file for details.

## Support

For issues and feature requests, please create an issue in the repository.