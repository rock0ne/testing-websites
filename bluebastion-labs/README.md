# BlueBastion Labs - Secure Web & API Stack

A comprehensive secure web and API stack for learning defensive security practices.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        BlueBastion Labs Environment                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │ Windows 11   │    │ Windows      │    │ Ubuntu Web Server        │  │
│  │ Endpoints    │◄──►│ Server AD    │◄──►│ (API + Web App)          │  │
│  │ (Lab VMs)    │    │ (Lab VM)     │    │ - Node.js API            │  │
│  └──────────────┘    └──────────────┘    │ - Nginx Reverse Proxy    │  │
│         │                   │            │ - PostgreSQL             │  │
│         │                   │            └──────────────────────────┘  │
│         │                   │                        │                  │
│         ▼                   ▼                        ▼                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                Microsoft 365 / Defender Stack                    │   │
│  │  - Microsoft Defender for Endpoint                               │   │
│  │  - Microsoft Sentinel (SIEM)                                     │   │
│  │  - Azure AD / Entra ID                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Topic | Status |
|--------|-------|--------|
| 1 | Secure API Foundations | 🔄 In Progress |
| 2 | Web App Authorization | ⏳ Pending |
| 3 | Telemetry & Detection | ⏳ Pending |
| 4 | Purple-Team Validation | ⏳ Pending |
| 5 | Secure Deployment | ⏳ Pending |
| 6 | Awareness Enablement | ⏳ Pending |

## Directory Structure

```
bluebastion-labs/
├── api/                    # Secure API service
│   ├── src/               # Source code
│   ├── tests/             # Unit & integration tests
│   └── config/            # Configuration files
├── web/                    # Web application
├── tests/                  # End-to-end tests
├── infrastructure/         # IaC templates
├── detection/              # KQL queries, detection rules
└── docs/                   # Documentation, checklists
```

## Quick Start

```bash
cd api
npm install
npm run dev
```

## Security Controls Implemented

- ✅ JWT/OAuth 2.1 authentication
- ✅ Input validation (Joi/Zod)
- ✅ Rate limiting
- ✅ Security headers (Helmet)
- ✅ Structured logging (audit trail)
- ✅ RBAC authorization
- ✅ IDOR prevention
- ✅ CSRF protection
