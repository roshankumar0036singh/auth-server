export interface User {
  id: string;
  email: string;
  /** Present when the user has a name on file (server omits when empty). */
  firstName?: string;
  /** Present when the user has a name on file (server omits when empty). */
  lastName?: string;
  /** Whether the user's email address has been verified. */
  emailVerified: boolean;
  /** Whether time-based one-time-password MFA is enabled. */
  mfaEnabled: boolean;
  /** ISO 8601 timestamp of account creation. */
  createdAt: string;
  /** ISO 8601 timestamp of the last successful login, when available. */
  lastLoginAt?: string;
}

export interface Session {
  accessToken: string;
  refreshToken?: string;
  user?: User;
}

export interface AuthClientConfig {
  /** The base URL of your auth server (e.g. https://auth.example.com) */
  serverUrl: string;
  /** Your OAuth client ID, obtained from the /oauth/clients API */
  clientId: string;
  /**
   * Where to persist the session tokens.
   * - `'localStorage'` – survives tab close (browser only)
   * - `'sessionStorage'` – cleared on tab close (browser only)
   * - `'memory'` – no persistence, lost on page reload (default, SSR-safe)
   */
  storage?: 'localStorage' | 'sessionStorage' | 'memory';
  /** Custom storage key. Defaults to `auth_session_<clientId>` */
  storageKey?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data: T;
  error?: {
    message?: string;
    code?: string;
  };
}

export interface SessionInfo {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export interface AuditLog {
  id: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
}

export type AuthStateChangeCallback = (session: Session | null) => void;
