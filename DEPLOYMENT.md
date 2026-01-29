# 🚀 Deployment Guide

This project is containerized and published to **GitHub Container Registry (GHCR)**. You can deploy it to any platform that supports Docker.

**Docker Image URL:**
```
ghcr.io/roshankumar0036singh/auth-server:latest
```

---

## Prerequisite: Environment Variables

Usage of this server requires the following environment variables. Ensure these are set in your deployment platform's configuration dashboard.

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `APP_ENV` | Environment mode | `production` |
| `PORT` | Listening port | `8080` |
| `DATABASE_URL` | PostgreSQL Connection | `postgres://user:pass@host:5432/db` |
| `REDIS_URL` | Redis Connection | `redis://host:6379` |
| `JWT_ACCESS_SECRET` | Secret for Access Token | `strong-random-secret` |
| `JWT_REFRESH_SECRET` | Secret for Refresh Token | `another-strong-secret` |
| `GOOGLE_CLIENT_ID` | OAuth Client ID | `...` |
| `GOOGLE_CLIENT_SECRET` | OAuth Client Secret | `...` |
| `GITHUB_CLIENT_ID` | OAuth Client ID | `...` |
| `GITHUB_CLIENT_SECRET` | OAuth Client Secret | `...` |

---

## Option 1: Generic VPS (DigitalOcean, AWS, Linode)

The simplest way to run on a server with Docker installed.

1.  **SSH into your server**.
2.  **Pull the image**:
    ```bash
    docker pull ghcr.io/roshankumar0036singh/auth-server:latest
    ```
3.  **Run the container**:
    ```bash
    docker run -d \
      --name auth-server \
      -p 80:8080 \
      --restart unless-stopped \
      -e APP_ENV=production \
      -e PORT=8080 \
      -e DATABASE_URL="postgresql://..." \
      -e REDIS_URL="redis://..." \
      -e JWT_ACCESS_SECRET="secret" \
      -e JWT_REFRESH_SECRET="secret" \
      ghcr.io/roshankumar0036singh/auth-server:latest
    ```

---

## Option 2: Render.com (Detailed Guide)

Render is great because it offers managed PostgreSQL and Redis, making full-stack deployment easy.

### Step 1: Create Database (PostgreSQL)
1.  Go to your Render Dashboard.
2.  Click **New +** -> **PostgreSQL**.
3.  Name: `auth-db` (This is the Service/Instance Name).
4.  Database Name: `auth_db` (Optional, but good for clarity).
5.  Region: Choose one close to you (e.g., `Singapore`).
5.  Plan: `Free` (for testing) or `Starter`.
6.  Click **Create Database**.
7.  **Copy the `Internal DB URL`**. You will need this later as `DATABASE_URL`. postgresql://auth_db_6lwu_user:S7w0XWhecFYxDEyFegpXgpIk14PHm62f@dpg-d5tfhadactks73a6kijg-a/auth_db_6lwu

### Step 2: Create Redis (Key Value)
1.  Click **New +** -> **Key Value**.
    *   *Note: Render now calls its Redis-compatible service "Key Value".*
2.  Name: `auth-redis`.
3.  Region: **Must be same as Database** (e.g., `Singapore`).
4.  Plan: `Free` (for testing) or `Starter`.
5.  Click **Create Key Value**.
6.  **Copy the `Internal Connection URL`**. You will need this later as `REDIS_URL`.
    *   **Important**: This URL only works from within Render (i.e., your Auth Server). It **cannot** be accessed from your local computer. Ignore the "blocked internet traffic" warning; that is intentional security.

### Step 3: Deploy Auth Server
1.  Click **New +** -> **Web Service**.
2.  Select **"Deploy an existing image from a registry"**.
3.  Image URL: `ghcr.io/roshankumar0036singh/auth-server:latest`
4.  Click **Next**.
5.  Name: `auth-server`.
6.  Region: **Same as DB and Redis**.
7.  **Advanced** -> **Environment Variables**:
    *   `APP_ENV` = `production`
    *   `PORT` = `8080` (Render detects this, but good to be explicit)
    *   `DATABASE_URL` = [Paste Internal DB URL from Step 1]
    *   `REDIS_URL` = [Paste Internal Redis URL from Step 2]
    *   `JWT_ACCESS_SECRET` = [Generate a strong random string]
    *   `JWT_REFRESH_SECRET` = [Generate another strong random string]
    *   `GIN_MODE` = `release`
8.  Click **Create Web Service**.

### Step 4: Verification
- Wait for the build/deploy to finish.
- Visit your unique Render URL (e.g., `https://auth-server-xyz.onrender.com/health`).
- You should see `{"status":"ok"}`.
- Visit `/swagger/index.html` for API docs.

---

## Option 3: Railway.app

1.  Create a **New Project**.
2.  Select **"Deploy a Docker Image"**.
3.  Image URL: `ghcr.io/roshankumar0036singh/auth-server:latest`
4.  Add a **PostgreSQL** and **Redis** service to your project.
5.  Link the variables in the "Variables" tab.

---

## Option 4: Docker Compose (Self-Hosted Stack)

If you want to run the database and redis alongside the app on a single server, use the `docker-compose.yml` in this repo:

```bash
# 1. Clone or copy docker-compose.yml
curl -O https://raw.githubusercontent.com/roshankumar0036singh/auth-server/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/roshankumar0036singh/auth-server/main/.env.example
mv .env.example .env

# 2. Edit .env with production secrets
vi .env

# 3. Start everything
docker compose up -d
```
