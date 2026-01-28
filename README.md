# Authentication Server - Go + Gin

A production-ready authentication server built with Go and Gin framework, featuring JWT-based authentication, OAuth integration, MFA, and RBAC.

## 🚀 Features

### Phase 1 & 2 - ✅ Complete
- **Token Management**
  - 🔄 Refresh token rotation (DB-backed)
  - 🚫 Token blacklisting (Redis)
  - 📱 Device tracking (IP & User Agent)
  - 🔒 Session management (view & revoke active sessions)
  - 🚪 Secure logout (all devices or specific session)
  - 🛡️ Rate limiting (login attempts)
- **User Management**
  - 📧 Email/Password registration
  - 🔐 Bcrypt password hashing
  - 👤 Profile management
  - 🛡️ Protected routes with JWT middleware
- **Infrastructure**
  - 🐘 PostgreSQL database with GORM
  - 🚀 Redis integration
  - 🐳 Docker support

### Upcoming Phases
- 📧 Email verification
- 🔄 Password reset
- 🔐 Multi-factor authentication (TOTP)
- 👥 Role-based access control (RBAC)
- 🌐 OAuth (Google, GitHub)
- 📊 Audit logging

## 📋 Prerequisites

- Go 1.21+ ([Install](https://golang.org/dl/))
- PostgreSQL 15+ ([Install](https://www.postgresql.org/download/))
- Redis 7+ ([Install](https://redis.io/download))

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server
```

### 2. Install dependencies
```bash
go mod tidy
```

### 3. Setup environment variables
```bash
cp .env.example .env
```

Edit `.env` and configure your database and other settings:
```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/auth_server?sslmode=disable
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secret-jwt-key-change-this
JWT_REFRESH_SECRET=your-refresh-secret-key-change-this
```

### 4. Create database
```bash
createdb auth_server
```

### 5. Run the server
```bash
# Using Make
make run

# Or directly with Go
go run cmd/server/main.go
```

The server will start on `http://localhost:3000` 🎉

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api
```

### Endpoints

#### 1. Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "emailVerified": false,
    "mfaEnabled": false,
    "createdAt": "2024-01-01T00:00:00Z"
  }
}
```

#### 2. Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John"
    }
  }
}
```

#### 3. Get Current User (Protected)
```http
GET /api/auth/me
Authorization: Bearer <access-token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User retrieved successfully",
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  }
}
```

#### 4. Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### 5. Logout (Protected)
```http
POST /api/auth/logout
Authorization: Bearer <access-token>
```

### Health Check
```http
GET /health
```

## 🏗️ Project Structure

```
auth-server/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/                  # Configuration
│   ├── models/                  # Data models
│   ├── repository/              # Data access layer
│   ├── service/                 # Business logic
│   ├── handler/                 # HTTP handlers
│   ├── middleware/              # Middleware
│   ├── routes/                  # Route definitions
│   ├── dto/                     # Data transfer objects
│   └── utils/                   # Utility functions
├── migrations/                  # Database migrations
├── tests/                       # Tests
├── .env.example                 # Environment template
├── Makefile                     # Build commands
└── go.mod                       # Dependencies
```

## 🔧 Development

### Available Make Commands

```bash
make run            # Run the application
make build          # Build binary
make test           # Run tests
make test-coverage  # Run tests with coverage
make docker-up      # Start Docker containers
make docker-down    # Stop Docker containers
make lint           # Run linter
make fmt            # Format code
make tidy           # Tidy dependencies
```

### Running with Docker

```bash
# Start all services (app, postgres, redis)
make docker-up

# Stop all services
make docker-down
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test ./... -cover

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## 🔒 Security

- ✅ Passwords hashed with bcrypt (cost 12)
- ✅ JWT tokens with expiration (15 min access, 7 days refresh)
- ✅ CORS configured
- ✅ Input validation with Gin binding
- ⏳ Rate limiting (upcoming)
- ⏳ Token blacklisting (upcoming)

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENV` | Environment (development/production) | development |
| `PORT` | Server port | 3000 |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_REFRESH_SECRET` | Refresh token secret | - |

## 🚀 Deployment

### Build for Production

```bash
# Build optimized binary
make build-prod

# Output: bin/auth-server
```

### Deploy with Docker

```bash
# Build image
docker build -t auth-server:latest .

# Run container
docker run -p 3000:3000 --env-file .env auth-server:latest
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 👤 Author

**Roshan Kumar Singh**
- GitHub: [@roshankumar0036singh](https://github.com/roshankumar0036singh)

## 🙏 Acknowledgments

- Built with [Gin](https://gin-gonic.com/)
- ORM by [GORM](https://gorm.io/)
- JWT by [golang-jwt](https://github.com/golang-jwt/jwt)

---

Made with ❤️ using Go and Gin
