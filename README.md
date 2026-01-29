<a name="top"></a>

## Hey <𝚌𝚘𝚍𝚎𝚛𝚜/>! 👋

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=28&duration=2500&pause=1000&color=6366F1&center=true&vCenter=true&width=900&lines=Welcome+to+Auth+Server;Production-Ready+Go+Backend;Enterprise-Grade+JWT+%26+OAuth2;Built+with+Go+%2B+Gin+%2B+PostgreSQL;Your+Security+First+Microservice;Open+for+Collaborations!" alt="Typing SVG" />
</p>

<p align="center">
  <img src="./docs/assets/banner.png" alt="Auth Server Banner" width="1000" height="480"/>
</p>

<div align="center">

  <p>
    <a href="https://auth-server-4nmm.onrender.com/swagger/">
      <img src="https://img.shields.io/badge/API%20Docs-6366F1?style=for-the-badge&logo=swagger&logoColor=white">
    </a>
    <a href="https://github.com/roshankumar0036singh/auth-server/releases">
      <img src="https://img.shields.io/badge/Release-v1.0-orange?style=for-the-badge&logo=github&logoColor=white">
    </a>
    <a href="./LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white">
    </a>
  </p>

  <p>
    <img src="https://img.shields.io/github/repo-size/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/languages/count/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/stars/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/forks/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/last-commit/roshankumar0036singh/auth-server" />
  </p>

  <p>
    <img src="https://img.shields.io/github/issues-raw/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/issues-closed-raw/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/issues-pr-raw/roshankumar0036singh/auth-server" />
    <img src="https://img.shields.io/github/issues-pr-closed-raw/roshankumar0036singh/auth-server" />
  </p>

![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Gin](https://img.shields.io/badge/Gin-0081CB.svg?style=for-the-badge&logo=go&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)
![GORM](https://img.shields.io/badge/GORM-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)

</div>

<p align="center">
  <b>Auth Server</b> is a robust, production-ready authentication microservice built with <b>Go</b> and <b>Gin</b>. It provides a full OAuth 2.0 Provider implementation, MFA, and RBAC out of the box.
</p>

## 📖 About Auth Server

> [!NOTE]
> This project is designed to be the backbone of your's app security. It's not just a boilerplate, but a feature-complete service that handles user lifecycles, OAuth flows, and administrative management.

### ⚡ Feature Highlights

Auth Server is built on a modular architecture using **Clean Architecture** principles in Go. 
- **High Performance**: Optimized Gin routes and Redis caching.
- **Security Hardened**: CSP headers, CORS protection, and secure token rotation.
- **Enterprise Ready**: Full OAuth 2.0 Provider flow for 3rd party integrations.
- **Interactive Documentation**: Beautifully redesigned Swagger UI.

> [!IMPORTANT]
> You can directly explore the API using our hosted documentation:
> - **[Live Swagger Docs](https://auth-server-4nmm.onrender.com/swagger/)**
> - **[OAuth Test Client](https://github.com/roshankumar0036singh/auth-server/tree/main/cmd/oauth-test-client)**

---

## ✨ Features Checklist

> [!NOTE]  
> These features represent the current state of **Auth Server**. We are actively looking for contributors to expand these capabilities.

- [x] **JWT Core**: Access & Refresh token rotation with secure revocation.
- [x] **OAuth 2.0 Provider**: Complete Authorization Code flow for 1st & 3rd party apps.
- [x] **Multi-Factor Auth**: TOTP support (Google Authenticator / Authy compatibility).
- [x] **Social Login**: One-click sign-in with **Google** & **GitHub**.
- [x] **Role-Based Access**: Granular `admin` vs `user` permissions.
- [x] **Audit Logging**: Comprehensive tracking of security events.
- [x] **Rate Limiting**: Redis-backed protection for all auth endpoints.
- [x] **Email flow**: Verification, Password Reset, and Welcome emails.
- [x] **Docker Ready**: Multi-stage builds and Compose orchestration.
- [ ] **Webhooks**: Notify external systems on auth events (Coming Soon).
- [ ] **SAML Integration**: Enterprise SSO support (Open for Contribution).
- [ ] **SDKs**: Official Client SDKs for React, Flutter, and Go.

---

## 🛠️ Tech Stack

### Backend Infrastructure
- **Language**: Go 1.25+
- **Framework**: Gin Gonic
- **ORM**: GORM (PostgreSQL Driver)
- **Cache/Session**: Redis (Rate limiting & Token blacklist)

### Security Features
- **Hashing**: BCrypt
- **Auth Protocols**: OAuth 2.0, OpenID Connect (Partial), TOTP
- **Transport**: TLS-ready, CSP & Security Headers

---

## 🚀 Getting Started

### Prerequisites
- **Go 1.25+**
- **Docker & Docker Compose**
- **PostgreSQL 15+** & **Redis 7+**

### Installation

```bash
# Clone the repository
git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server

# Install dependencies
go mod download

# Set up environment
cp .env.example .env
```

### Running with Docker (Quickest)

```bash
docker compose up --build -d
```
Access the server at `http://localhost:8080` and docs at `/swagger/`.

---

## 🤝 Contributing & Community

> [!IMPORTANT]  
> We thrive on community contributions. Whether it's fixing a bug, improving docs, or proposing a new feature, your help is welcome!

### Join the Discussion
- 💬 **Discord Server** — [Join our community](https://discord.gg/your-link)
- 🧭 **GitHub Discussions** — [Share ideas](https://github.com/roshankumar0036singh/auth-server/discussions)

### How to Contribute
1. **Fork** the project.
2. **Branch** off (`git checkout -b feature/AmazingFeature`).
3. **Commit** your changes (`git commit -m 'feat: add some amazing feature'`).
4. **Push** to the branch (`git push origin feature/AmazingFeature`).
5. **Open a PR**!

---

## 📄 License & Author

Distributed under the **MIT License**. See `LICENSE` for more information.

**Roshan Kumar Singh** - [@roshankumar0036singh](https://github.com/roshankumar0036singh)

<a href="#top"><img src="https://img.shields.io/badge/⬆-Back%20to%20Top-red?style=for-the-badge" align="right"/></a>

<div align="center">
  <br />
  <b>Built with ❤️ using Go and Gin</b>
</div>
