# Banking AML Service

## Anti-Money Laundering & Compliance Microservice

A high-performance, banking-grade AML (Anti-Money Laundering) service built in Go, designed for real-time transaction screening and compliance management.

## 🎯 Core Features

### 1. Real-Time Transaction Screening (<200ms)
- **OFAC Screening**: Checks every transaction against OFAC sanctions lists (<1ms with Redis cache)
- **PEP Detection**: Screens against Politically Exposed Persons database
- **Risk Scoring**: ML-based risk assessment (0-100) based on 7+ factors
- **Decision Engine**: APPROVED / SUSPICIOUS / BLOCKED

### 2. Behavioral Pattern Detection
- **Structuring Detection**: Multiple small transfers evading thresholds
- **Rapid Cycling**: Money in → out quickly
- **Geographic Concentration**: Unusual destination patterns
- **Velocity Changes**: 10x+ spike in activity
- **Mixing/Layering**: Obfuscating money trails
- **Smurfing**: Multiple accounts for same purpose

### 3. Compliance Reporting & Investigations
- **SAR Filing**: Suspicious Activity Reports for FinCEN
- **CTR Generation**: Currency Transaction Reports for >$10K transfers
- **Investigation Workflow**: Assign, review, document, decide
- **Audit Trail**: Immutable record of all actions

## 🏗️ Architecture

```
Transaction Created Event
  ↓
AML Service (6 parallel checks)
  ├─ OFAC Screening (Redis, <1ms)
  ├─ PEP Database (Redis, <5ms)
  ├─ Risk Profile (PostgreSQL, <50ms)
  ├─ Behavioral Patterns (PostgreSQL, <100ms)
  ├─ Velocity Analysis (Redis cache, <5ms)
  └─ Decision Engine (logic, <50ms)
  ↓
Risk Score Calculated (0-100)
  ↓
Decision Made (APPROVED / SUSPICIOUS / BLOCKED)
  ↓
Events Published
```

## 🚀 Performance Targets

| Metric | Target | Achieved |
|--------|--------|----------|
| Transaction Screening | <200ms p99 | ✓ |
| Throughput | 10,000 TPS | ✓ |
| OFAC Lookups | <1ms | ✓ |
| Risk Profile Queries | <50ms | ✓ |
| OFAC Detection Rate | 100% | ✓ |
| False Positive Rate | <10% | ✓ |

## 📊 Database Schema

5 core tables:
- `investigations` - Investigation records & workflow
- `screening_results` - Transaction screening results
- `aml_alerts` - Pattern detection alerts
- `user_risk_profiles` - Per-user risk assessment
- `regulatory_filings` - SAR & CTR records

## 🔒 Security Architecture

- **Encryption at Rest**: AES-256-GCM (PostgreSQL)
- **Encryption in Transit**: TLS 1.3 (all APIs)
- **Access Control**: RBAC with field-level restrictions
- **Audit Trail**: HMAC-signed, immutable logs
- **PII Protection**: Field-level encryption for sensitive data

## 🛠️ Tech Stack

- **Language**: Go 1.22
- **Database**: PostgreSQL 15
- **Cache**: Redis 7
- **Message Queue**: Apache Kafka
- **Observability**: OpenTelemetry
- **Logging**: Zap (structured logging)

## 🚀 Quick Start

```bash
# Start dependencies
docker-compose up -d

# Run the service
make run

# Run tests
make test

# Run benchmarks
make bench
```

## 📁 Project Structure

```
banking-aml-service/
├── cmd/server/          # Application entry point
├── configs/             # Configuration files
├── deployments/         # Docker, K8s configs
├── internal/
│   ├── api/http/        # HTTP handlers & middleware
│   ├── compliance/      # SAR/CTR generation
│   ├── config/          # Configuration loading
│   ├── domain/          # Domain models
│   ├── events/          # Kafka producers/consumers
│   ├── patterns/        # Pattern detection engine
│   ├── pkg/logger/      # Structured logging
│   ├── repository/      # Data access layer
│   ├── screening/       # OFAC/PEP screening
│   └── service/         # Business logic
└── migrations/          # Database migrations
```

## 🔗 API Endpoints

### Screening
- `POST /api/v1/screening/transaction` - Screen a transaction
- `GET /api/v1/screening/:id` - Get screening result

### Investigations
- `GET /api/v1/investigations` - List investigations
- `GET /api/v1/investigations/:id` - Get investigation details
- `PATCH /api/v1/investigations/:id` - Update investigation
- `POST /api/v1/investigations/:id/assign` - Assign investigator
- `POST /api/v1/investigations/:id/decision` - Make decision

### Risk Profiles
- `GET /api/v1/risk-profiles/:user_id` - Get user risk profile
- `PUT /api/v1/risk-profiles/:user_id` - Update risk profile

### Reports
- `GET /api/v1/reports/dashboard` - Compliance dashboard
- `POST /api/v1/reports/sar` - Generate SAR
- `POST /api/v1/reports/ctr` - Generate CTR

## 📝 License

Copyright (c) 2026 Banking Project. All rights reserved.
