<!-- markdownlint-disable MD013 MD033 MD036 MD041 -->

<div align="center">

# `@authserver/client`

**The TypeScript SDK for Auth Server**

[![npm](https://img.shields.io/npm/v/%40authserver%2Fclient?style=flat-square&logo=npm&logoColor=white&color=CB3837)](https://www.npmjs.com/package/@authserver/client)
[![downloads](https://img.shields.io/npm/dm/%40authserver%2Fclient?style=flat-square&color=CB3837)](https://www.npmjs.com/package/@authserver/client)
[![bundle size](https://img.shields.io/bundlephobia/minzip/%40authserver%2Fclient?style=flat-square&label=minzip)](https://bundlephobia.com/package/@authserver/client)
[![TypeScript](https://img.shields.io/badge/TypeScript-SDK-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://github.com/roshankumar0036singh/auth-server/tree/main/clients/ts/src)
[![React](https://img.shields.io/badge/React-18+-149ECA?style=flat-square&logo=react&logoColor=white)](#react-quick-start)
[![License](https://img.shields.io/badge/license-MIT-22C55E?style=flat-square)](https://github.com/roshankumar0036singh/auth-server/blob/main/LICENSE)

[Get a client ID](#get-a-client-id) | [Quick start](#quick-start) | [React](#react-quick-start) | [Next.js](#nextjs) | [Node.js](#nodejs-quick-start) | [API overview](#api-overview) | [Full documentation](https://github.com/roshankumar0036singh/auth-server/blob/main/docs/sdk/ts.md)

</div>

---

`@authserver/client` is a complete authentication client for the [Auth Server](https://github.com/roshankumar0036singh/auth-server): email/password, social login (Google, GitHub), MFA, email verification, password reset, session management, and audit logs — fully typed, with React bindings.

### Why this SDK

- **Zero runtime dependencies** — uses the native Fetch API; nothing to audit, tiny install.
- **Automatic token refresh** — transparently refreshes and retries once after a `401`; concurrent refreshes are de-duplicated.
- **Session persistence** — `localStorage`, `sessionStorage`, or in-memory (SSR-safe).
- **First-class TypeScript** — typed methods, `User`/`Session` types, and a structured `AuthError`.
- **React bindings** — `AuthProvider` + `useAuth()` from `@authserver/client/react`.
- **Hosted or self-hosted** — point it at the hosted server to get started in minutes, or run your own (Docker Compose) and change one URL. No lock-in.

## Installation

The fastest way to start a new project is the scaffolder, which generates a
ready-to-run Next.js, React, or Node.js app wired up with this SDK:

```bash
npm create auth-app@latest my-app
```

To add the SDK to an existing project:

```bash
npm install @authserver/client
```

React applications also need React and React DOM `>=18.0.0`:

```bash
npm install @authserver/client react react-dom
```

The package ships ESM, CommonJS, and TypeScript declarations. Node.js applications need a global Fetch API implementation; Node.js 18 and later include one.

## Get a Client ID

Every client needs two things: a **`serverUrl`** (which auth server to talk to) and a **`clientId`** (which application is talking to it). The fastest way to start is the **hosted server** — no infrastructure to run:

```
serverUrl: https://auth-server-4nmm.onrender.com
```

Create a `clientId` against it in two steps:

```bash
# 1. Register an account (this account owns your client)
curl -X POST https://auth-server-4nmm.onrender.com/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a-strong-password","firstName":"Your","lastName":"Name"}'

# 2. Log in to get an access token, then register an OAuth client.
#    Replace <ACCESS_TOKEN> with the accessToken from the login response.
curl -X POST https://auth-server-4nmm.onrender.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a-strong-password"}'

curl -X POST https://auth-server-4nmm.onrender.com/api/auth/oauth/clients \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -d '{
        "name": "My App",
        "redirect_uris": ["http://localhost:5173/callback"],
        "scopes": ["read:profile", "read:email"]
      }'
```

The last response contains your client:

```json
{
  "success": true,
  "data": {
    "client_id": "abc123...",
    "client_secret": "shown-only-once-store-it-safely",
    "name": "My App",
    "redirect_uris": ["http://localhost:5173/callback"],
    "scopes": ["read:profile", "read:email"]
  }
}
```

Use the `client_id` value as the `clientId` below. The `client_secret` is shown only once — store it somewhere safe if your integration needs it (it is **not** required for the browser/email-password flows in the quick start). The hosted server is great for prototyping and demos; for production, treat it as a shared environment and consider self-hosting.

> [!TIP]
> **Prefer to self-host?** The server is open source (Go + PostgreSQL + Redis) and runs with one command:
> `git clone https://github.com/roshankumar0036singh/auth-server && cd auth-server && docker compose up -d`.
> Then set `serverUrl` to your own origin (e.g. `http://localhost:3000`) and mint a `clientId` exactly as above. Everything in this SDK works identically against a self-hosted server — only the URL changes. See the [server README](https://github.com/roshankumar0036singh/auth-server#readme) for configuration.

## Quick Start

Create one client for your browser application:

```ts
import { AuthClient, AuthError } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: 'https://auth-server-4nmm.onrender.com',
  clientId: 'your_oauth_client_id',
  storage: 'localStorage', // 'sessionStorage' | 'memory' (default)
});

// Listen to auth state changes
const unsubscribe = auth.onAuthStateChanged((session) => {
  console.log(session ? 'Logged in' : 'Logged out');
});

try {
  const session = await auth.login(
    'ada@example.com',
    'correct-horse-battery-staple',
  );

  console.log('Signed in:', session.user?.email);
} catch (error) {
  if (error instanceof AuthError) {
    console.error(error.code, error.status, error.message);
  } else {
    throw error;
  }
}
```

- `serverUrl` is the auth server origin without `/api`.
- `clientId` is required, including for email/password integrations.
- Storage defaults to `memory`. Browser applications can choose `localStorage` or `sessionStorage`.

### Observe Auth State

```ts
const unsubscribe = auth.onAuthStateChanged((session) => {
  console.log(session ? 'Signed in' : 'Signed out');
});

// Remove the listener when it is no longer needed.
unsubscribe();
```

### Read the Current User

```ts
const user = await auth.getUser();
console.log(`Welcome, ${user.firstName ?? user.email}`);
```

### Social Login (browser)

Start a Google/GitHub flow, optionally passing where the auth server should send
the browser back (must be a registered redirect URI; defaults to the current page):

```ts
auth.loginWithGoogle('https://your-app.com/auth/callback');
```

On your callback page, complete the redirect — it reads the tokens from the URL,
stores the session, and cleans the address bar:

```ts
const session = auth.completeOAuthRedirect();
if (session) {
  // signed in
}
```

## React Quick Start

Create the client outside React components so renders do not replace it:

```ts
// auth.ts
import { AuthClient } from '@authserver/client';

const authClient = new AuthClient({
  serverUrl: 'https://auth-server-4nmm.onrender.com',
  clientId: 'your_oauth_client_id',
  storage: 'localStorage',
});
```

Wrap the application:

```tsx
// App.tsx
import { AuthProvider } from '@authserver/client/react';
import { authClient } from './auth';
import { Account } from './Account';

export function App() {
  return (
    <AuthProvider client={authClient}>
      <Account />
    </AuthProvider>
  );
}
```

Use auth state and actions from any descendant:

```tsx
// Account.tsx
import { useAuth } from '@authserver/client/react';

export function Account() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();

  if (isLoading) return <p>Loading session...</p>;

  if (!isAuthenticated) {
    return (
      <button
        type="button"
        onClick={() => void login('ada@example.com', 'your-password')}
      >
        Sign in
      </button>
    );
  }

  return (
    <section>
      <p>Signed in as {user?.email ?? 'current user'}</p>
      <button type="button" onClick={() => void logout()}>
        Sign out
      </button>
    </section>
  );
}
```

## Next.js

`@authserver/client/nextjs` adds server-side auth for Next.js. Tokens are stored
in **httpOnly cookies on your app's own domain** (a cookie proxy), so Server
Components, Route Handlers, middleware, and `getServerSideProps` can all read the
session. It works with both the App Router and the Pages Router and has no extra
runtime dependencies.

Create one server instance:

```ts
// lib/auth.ts
import { createAuthServer } from '@authserver/client/nextjs';

export const authServer = createAuthServer({
  serverUrl: process.env.AUTH_SERVER_URL!, // e.g. https://auth-server-4nmm.onrender.com
  clientId: process.env.AUTH_CLIENT_ID!,
});
```

### App Router

Mount the auth routes with a catch-all Route Handler:

```ts
// app/api/auth/[...authserver]/route.ts
import { authServer } from '@/lib/auth';

export const { GET, POST } = authServer.handlers;
// Exposes POST /api/auth/login, /logout, /refresh and GET /api/auth/session
```

Read the session in a Server Component (validated against `/api/auth/me`):

```tsx
// app/dashboard/page.tsx
import { cookies } from 'next/headers';
import { authServer } from '@/lib/auth';

export default async function Dashboard() {
  const session = await authServer.getSession(await cookies());
  if (!session) return <a href="/login">Sign in</a>;
  return <p>Welcome, {session.user.firstName ?? session.user.email}</p>;
}
```

Protect routes with middleware:

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { authServer } from '@/lib/auth';

export function middleware(req: Request) {
  return authServer.middleware({ publicPaths: ['/', '/login'] })(req) ?? NextResponse.next();
}

export const config = { matcher: ['/dashboard/:path*'] };
```

Log in from a Client Component by posting to the proxy route — the httpOnly
cookies are set for you:

```tsx
'use client';

async function signIn(email: string, password: string) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error('Login failed');
  window.location.href = '/dashboard';
}
```

### Pages Router

Gate a page in `getServerSideProps`:

```ts
import { authServer } from '@/lib/auth';

export const getServerSideProps = async (ctx) => {
  const session = await authServer.getSession(ctx.req);
  if (!session) return { redirect: { destination: '/login', permanent: false } };
  return { props: { user: session.user } };
};
```

Mount the same login/logout/refresh routes as an API route:

```ts
// pages/api/auth/[...authserver].ts
import { authServer } from '@/lib/auth';

export default authServer.toNodeHandler();
```

### Social login

The catch-all handler also serves `GET /api/auth/callback`. **Register that exact
URL as a redirect URI on your OAuth client**, then start the flow with the URL
helpers, passing your callback URL:

```tsx
<a href={authServer.googleLoginUrl('https://your-app.com/api/auth/callback')}>
  Continue with Google
</a>
```

The auth server validates the redirect URI against your client's registered URIs,
then redirects the browser back to `/api/auth/callback?access_token=…&refresh_token=…`.
The handler moves those tokens into httpOnly cookies and `302`s to
`afterLoginPath` (default `/`), so the tokens never linger in the address bar.

### Token refresh

The access token is short-lived. When a browser request gets a `401`, call
`POST /api/auth/refresh` (it reads the refresh cookie and rotates both cookies),
then retry. `getSession()` does not refresh on its own because Server Components
cannot set cookies.

## Node.js Quick Start

Node.js uses in-memory sessions. Create a separate client for each isolated user session; never share a token-bearing client between users.

```ts
import { AuthClient } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: process.env.AUTH_SERVER_URL ?? 'http://localhost:3000',
  clientId: process.env.AUTH_CLIENT_ID ?? 'local-node-client',
});

await auth.login(
  process.env.AUTH_EMAIL ?? '',
  process.env.AUTH_PASSWORD ?? '',
);

const user = await auth.getUser();
console.log(`Authenticated as ${user.email}`);

await auth.logout();
```

## Runnable Examples

Complete, copy-pasteable projects live in [`examples/`](./examples):

- [`examples/node`](./examples/node) — a Node.js script (login → read user → logout).
- [`examples/react-vite`](./examples/react-vite) — a minimal React + Vite app using `AuthProvider` and `useAuth()`.

Both run against the hosted server by default and against your own server by changing one environment variable.

## Session Behavior

- The client attaches its current access token to SDK requests.
- After a request returns `401`, the client refreshes and retries once when a refresh token is available.
- Concurrent refresh calls share one in-flight request.
- `logout()` clears local tokens even when server-side logout fails.
- Persisted sessions contain tokens only; fetch the current user with `getUser()`.

> [!CAUTION]
> Browser storage tokens are readable by JavaScript running on the page. Prevent cross-site scripting, apply a strict Content Security Policy, avoid logging tokens, and select the shortest persistence period your application needs.

## Error Handling

SDK request failures throw `AuthError`:

```ts
import { AuthError } from '@authserver/client';

try {
  await auth.getUser();
} catch (error) {
  if (error instanceof AuthError) {
    console.error({
      code: error.code,
      status: error.status,
      message: error.message,
    });
  }
}
```

Every `AuthError` has a `code` (string), a `status` (HTTP status, or `0` for client-side errors), and a `message`. The SDK generates these codes locally:

| Code | `status` | Meaning |
| --- | --- | --- |
| `NETWORK_ERROR` | `0` | The request never reached the server (offline, DNS, CORS, wrong `serverUrl`). |
| `SESSION_EXPIRED` | `401` | A `401` was returned and the automatic refresh failed; the local session has been cleared. Prompt the user to log in again. |
| `NO_REFRESH_TOKEN` | `401` | `refresh()` was called but no refresh token is stored. |
| `BROWSER_ONLY` | `0` | `loginWithGoogle()` / `loginWithGitHub()` was called outside a browser. |
| `API_ERROR` | varies | The server returned a non-`2xx` response without a structured error code. |

Any other `code` and `message` originates from the server (for example validation failures on `register`), passed through unchanged so you can branch on `error.code` and `error.status`.

## API Overview

| Area | Methods |
| --- | --- |
| Authentication | `register`, `login`, `loginMfa`, `refresh`, `logout`, `logoutAll` |
| Session state | `setSession`, `getAccessToken`, `getRefreshToken`, `isAuthenticated`, `onAuthStateChanged` |
| Social login | `loginWithGoogle`, `loginWithGitHub` |
| Account | `getUser`, `updateProfile`, `changePassword`, `deleteAccount` |
| Verification | `verifyEmail`, `resendVerification`, `forgotPassword`, `resetPassword` |
| MFA | `enableMfa`, `verifyMfa`, `loginMfa` |
| Security activity | `getSessions`, `revokeSession`, `getAuditLogs` |
| React | `AuthProvider`, `useAuth` from `@authserver/client/react` |
| Next.js (server) | `createAuthServer` → `handlers`, `getSession`, `middleware`, `toNodeHandler`, `googleLoginUrl`, `githubLoginUrl` from `@authserver/client/nextjs` |

See the **[complete TypeScript SDK guide and API reference](https://github.com/roshankumar0036singh/auth-server/blob/main/docs/sdk/ts.md)** for configuration, method signatures, exported types, MFA, OAuth redirects, session lifecycle, and production guidance.

## Local Development

```bash
cd clients/ts
npm ci
npm run build
```

The build writes ESM, CommonJS, and declaration files to `dist`.

## License

[MIT](https://github.com/roshankumar0036singh/auth-server/blob/main/LICENSE)
