<!-- markdownlint-disable MD013 MD033 MD036 MD041 -->

<div align="center">

# `@authserver/client`

**The TypeScript SDK for Auth Server**

[![npm](https://img.shields.io/npm/v/%40authserver%2Fclient?style=flat-square&logo=npm&logoColor=white&color=CB3837)](https://www.npmjs.com/package/@authserver/client)
[![TypeScript](https://img.shields.io/badge/TypeScript-SDK-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://github.com/roshankumar0036singh/auth-server/tree/main/clients/ts/src)
[![React](https://img.shields.io/badge/React-18+-149ECA?style=flat-square&logo=react&logoColor=white)](#react-quick-start)
[![License](https://img.shields.io/badge/license-MIT-22C55E?style=flat-square)](https://github.com/roshankumar0036singh/auth-server/blob/main/LICENSE)

[Quick start](#quick-start) | [React](#react-quick-start) | [Node.js](#nodejs-quick-start) | [API overview](#api-overview) | [Full documentation](https://github.com/roshankumar0036singh/auth-server/blob/main/docs/sdk/ts.md)

</div>

---

`@authserver/client` provides typed authentication methods, session persistence, automatic token refresh after `401` responses, structured errors, and React bindings.

## Installation

```bash
npm install @authserver/client
```

React applications also need React and React DOM `>=18.0.0`:

```bash
npm install @authserver/client react react-dom
```

The package ships ESM, CommonJS, and TypeScript declarations. Node.js applications need a global Fetch API implementation; Node.js 18 and later include one.

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
console.log(`Welcome, ${user.first_name}`);
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

Common client-generated codes are `NETWORK_ERROR`, `SESSION_EXPIRED`, `NO_REFRESH_TOKEN`, `BROWSER_ONLY`, and `API_ERROR`.

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

See the **[complete TypeScript SDK guide and API reference](https://github.com/roshankumar0036singh/auth-server/blob/main/docs/sdk/ts.md)** for configuration, method signatures, exported types, MFA, OAuth redirects, session lifecycle, and production guidance.

## Repository Compatibility

> [!WARNING]
> The SDK source and Go server source in the current repository checkout use different JSON field casing in several request and response contracts. Social-login callbacks also return JSON rather than automatically restoring the frontend session. Review the [full compatibility notes](https://github.com/roshankumar0036singh/auth-server/blob/main/docs/sdk/ts.md#current-repository-compatibility) before integrating this checkout.

## Local Development

```bash
cd clients/ts
npm ci
npm run build
```

The build writes ESM, CommonJS, and declaration files to `dist`.

## License

[MIT](https://github.com/roshankumar0036singh/auth-server/blob/main/LICENSE)
