# Changelog

## [2.0.0] - 2026-06-21

### Changed
- **BREAKING**: `AdminClient.listUsers()` now returns a paginated structure containing `{ users, meta }` instead of a flat array of users.
- **BREAKING**: `AuthClient.completeOAuthRedirect()` is now `async` and returns a `Promise<Session | null>`. Callers must `await` it.
- **BREAKING**: The `StorageAdapter` interface now requires `getItem`, `setItem`, and `removeItem` to return `Promise`s.

**Migration Guide**:
```typescript
// Old
const users = await admin.listUsers();

// New
const { users } = await admin.listUsers();
```

## [1.0.5] - 2026-06-19

### Added
- `VERSION` export for the current SDK version.
- `AdminClient` class to perform administrative actions (`listUsers`, `lockUser`, `unlockUser`, `deleteUser`). Exported via `@authserver/client/admin`.
- Proactive Token Refresh: Tokens automatically refresh 30 seconds before expiration.
- Fine-grained Event Emitter: `on()` method added with specific events (`session`, `login`, `logout`, `token:refreshed`, `error`).
- Fetch Retry with Exponential Backoff: `retries` and `retryDelay` settings added to `AuthClientConfig` to automatically retry network failures.
- Server Keep-Alive Ping: `keepAlive` and `keepAliveInterval` settings added to `AuthClientConfig` to optionally ping the server's health endpoint to prevent sleep.
- `disableMfa(password, code)` method to disable TOTP multi-factor authentication.
- React hooks: `useUser()` and `useSession()`.
- React component: `<ProtectedRoute>`.
- JSDoc annotations for core methods.
- Comprehensive `vitest` unit test suite.

### Breaking Changes
- `loginMfa(email, code)` signature changed to `loginMfa(mfaToken, code)`. 
  Replace the first argument with the `mfaToken` returned by `login()` when `mfaRequired: true`.

### Fixed
- Fixed a bug where a missing `refreshToken` would persist the previous session's refresh token due to `undefined` handling.

## [1.0.4] - 2026-06-18

### Fixed
- Support for backward compatibility and deduplication of token logic.
- Next.js cookie handling improvements.

## [1.0.0] - 2026-06-15

### Added
- Initial release.
- Core authentication features: register, login, logout, refresh.
- Social login (Google, GitHub).
- Next.js adapter with HTTP-only cookie proxy.
- React bindings (`AuthProvider`, `useAuth`).
- MFA support.
