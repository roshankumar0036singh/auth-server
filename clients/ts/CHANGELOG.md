# Changelog

All notable changes to `@authserver/client` are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`User` type now matches the server response.** The `User` interface
  previously declared `isVerified`, `role`, `updatedAt`, and `profileImage`,
  none of which the server returns from `/api/auth/me`, `login`, or `register`.
  These have been replaced with the fields the server actually sends:
  `emailVerified`, `lastLoginAt`, and optional `firstName`/`lastName`. Code that
  read `user.isVerified` should now read `user.emailVerified`.
- Documentation: corrected the "Read the Current User" example
  (`user.first_name` → `user.firstName`) and removed the outdated repository
  compatibility warning — the SDK and server both use camelCase JSON.

### Added

- **Next.js adapter** (`@authserver/client/nextjs`). `createAuthServer()` provides
  an httpOnly cookie proxy (`handlers` for App Router, `toNodeHandler()` for Pages
  Router), `getServerSession()` validated against `/api/auth/me`, route-protection
  `middleware()`, a social-login `callback` handler, and social-login URL helpers.
  Works in the Node.js and Edge runtimes with no extra runtime dependencies.
  `next` is an optional peer dependency.
- **Working social login.** `loginWithGoogle()`/`loginWithGitHub()` now accept a
  `redirectUri`, and `completeOAuthRedirect()` finishes the flow in the browser by
  reading tokens from the callback URL and cleaning the address bar. (Requires the
  paired auth-server change that validates the redirect URI and redirects back to
  your app with tokens instead of returning JSON.)
- "Get a Client ID" guide covering both the hosted server and self-hosting.
- Runnable `examples/` (Node.js script and a React + Vite app).
- Expanded npm keywords, `engines`, `bugs`, and monorepo `repository.directory`
  for correct source links and provenance on npm.

## [1.0.2]

- Initial public releases: typed `AuthClient`, automatic token refresh after
  `401`, session persistence, social login, MFA, email verification, password
  reset, session management, audit logs, and React bindings
  (`AuthProvider` / `useAuth`).
