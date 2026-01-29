# Auth Server - Production-Ready Authentication

<div align="center">

<h1 align="center">Secure Your App <img src="https://raw.githubusercontent.com/MartinHeinz/MartinHeinz/master/wave.gif" width="30px"></h1>

<!-- <img src="./docs/assets/banner.png" alt="Auth Server Banner" width="1000" /> -->

[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=25&pause=1000&color=1E3A8A&center=true&vCenter=true&width=435&lines=Secure.;Scalable.;Go-Powered.;Auth.)](https://git.io/typing-svg)

<p align="center">
  <a href="http://localhost:8080/swagger/index.html">
    <img src="https://img.shields.io/badge/API_DOCS-4CAF50?style=for-the-badge&logo=swagger&logoColor=white" alt="Swagger Docs" />
  </a>
  <a href="./docs">
    <img src="https://img.shields.io/badge/DOCUMENTATION-007ACC?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation" />
  </a>
  <a href="https://github.com/roshankumar0036singh/auth-server/releases">
    <img src="https://img.shields.io/github/v/release/roshankumar0036singh/auth-server?style=for-the-badge&logo=github&color=orange" alt="Release" />
  </a>
</p>

<p align="center">
  <!-- Tech Stack Badges -->
  <img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Gin_Framework-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Gin" />
  <img src="https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
</p>

<p align="center">
  <a href="https://github.com/roshankumar0036singh/auth-server/issues">
    <img src="https://img.shields.io/github/issues/roshankumar0036singh/auth-server?style=for-the-badge&logo=github" alt="Open Issues" />
  </a>
  <a href="https://github.com/roshankumar0036singh/auth-server/pulls">
    <img src="https://img.shields.io/github/issues-pr/roshankumar0036singh/auth-server?style=for-the-badge&logo=github" alt="Pull Requests" />
  </a>
  <a href="https://github.com/roshankumar0036singh/auth-server/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/roshankumar0036singh/auth-server?style=for-the-badge&logo=github" alt="License" />
  </a>
</p>

</div>

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
📋 Overview
</h2>

**Auth Server** is a robust, production-ready authentication and authorization microservice built with **Go (Golang)** and **Gin**. It provides a complete solution for modern applications, featuring JWT management, OAuth2 social login, Multi-Factor Authentication (MFA), Role-Based Access Control (RBAC), and enterprise-grade security hardening.

### Key Benefits

- **High Performance**: Built on Go and Gin for blazing fast response times.
- **Security First**: Implements industry standards (BCrypt, HS256, CSRF protection, Security Headers).
- **Scalable**: Stateless JWT architecture with Redis for session management and rate limiting.
- **Developer Ready**: Comprehensive Swagger API documentation and easy Docker deployment.
- **Feature Rich**: Out-of-the-box support for Email verification, Password resets, and Social Login.

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
✨ Features
</h2>

### core Authentication

| Feature | Description |
|---------|-------------|
| **JWT Management** | Access (15m) & Refresh (7d) tokens with secure rotation |
| **User Onboarding** | Email/Password registration with verification flow |
| **Password Management** | Secure hashing (BCrypt), complexity rules, and reset flows |
| **Session Control** | Device tracking, remote logout, and token revocation |

### Advanced Security

| Feature | Description |
|---------|-------------|
| **MFA (2FA)** | Time-based One-Time Password (TOTP) support (Google Authenticator) |
| **RBAC** | Granular permission system with `user` and `admin` roles |
| **Social Login** | OAuth 2.0 integration for **Google** and **GitHub** |
| **Rate Limiting** | Redis-backed global and per-IP safeguards against abuse |
| **Audit Logging** | Detailed tracking of all security-critical events |

### Infrastructure & DevOps

| Feature | Description |
|---------|-------------|
| **Dockerized** | Multi-stage Dockerfile and Docker Compose setup |
| **CI/CD** | Automated testing and build pipeline via GitHub Actions |
| **API Docs** | Interactive Swagger/OpenAPI documentation |
| **Monitoring** | Health checks and structured logging |

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
🛠️ Technology Stack
</h2>

### Core
- **Go 1.25+** - Language
- **Gin Web Framework** - HTTP handling
- **GORM** - ORM for database interaction

### Storage
- **PostgreSQL** - Primary relationship database
- **Redis** - Cache, Rate Limiting, and Session revocation

### Libraries & Tools
- **Golang-JWT** - Token signing and verification
- **Pquerna/OTP** - TOTP generation for MFA
- **Viper** - Configuration management
- **Swaggo** - API Documentation generation
- **Testify** - Unit and Integration testing

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
🚀 Quick Start
</h2>

### Prerequisites

- **Go 1.25+** ([Download](https://golang.org/dl/))
- **Docker & Docker Compose** (Recommended)
- **PostgreSQL 15+** (If running locally)
- **Redis 7+** (If running locally)

### Installation

```bash
# Clone the repository
git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server

# Install dependencies
go mod download
```

### Configuration

1. **Copy environment template**:
   ```bash
   cp .env.example .env
   ```

2. **Configure credentials** in `.env`:
   - Database connection string (`DATABASE_URL`)
   - Redis URL (`REDIS_URL`)
   - JWT Secrets (Critical security keys)
   - OAuth Credentials (Google/GitHub Client IDs)

### Running with Docker (Recommended)

```bash
# Start all services (App, Postgres, Redis)
make docker-up
# or
docker compose up --build -d
```

The server will start on `http://localhost:8080`.

### Running Locally

```bash
# Ensure Postgres and Redis are running first
make run
# or
go run cmd/server/main.go
```

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
📚 Documentation
</h2>

- **[API Documentation (Swagger)](http://localhost:8080/swagger/index.html)** - Interactive Endpoint Reference
- **[Setup Guide](./README.md#configuration)** - Configuration details
- **[Deployment](./README.md#deployment)** - Prod deployment instructions

### Main Endpoints

- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Authenticate
- `GET /api/auth/me` - Get profile (Protected)
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/mfa/verify` - Verify 2FA

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
🤝 Contributing
</h2>

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'feat: Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
📄 License
</h2>

This project is licensed under the **MIT License**.

---

<h2 align="center" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #1E3A8A; font-weight: 700; margin-top: 2rem;">
👤 Author
</h2>

**Roshan Kumar Singh**
- GitHub: [@roshankumar0036singh](https://github.com/roshankumar0036singh)

---

<div align="center">

**Built with ❤️ using Go and Gin**

[⬆ Back to Top](#auth-server---production-ready-authentication)

</div>
