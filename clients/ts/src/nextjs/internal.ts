/**
 * Framework-free helpers for the Next.js adapter. Everything here relies only on
 * Web-standard APIs (Request/Response/Headers, atob) so it runs in the Node.js
 * and Edge runtimes without pulling `next` into the bundle.
 */

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  maxAge?: number;
}

/** Serialize a cookie into a `Set-Cookie` header value. */
export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path ?? '/'}`);
  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
  }
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  parts.push(`SameSite=${capitalize(options.sameSite ?? 'lax')}`);
  return parts.join('; ');
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Parse a `Cookie` request header into a name→value map. */
export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const pair of header.split(';')) {
    const index = pair.indexOf('=');
    if (index === -1) continue;
    const key = pair.slice(0, index).trim();
    const val = pair.slice(index + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  }
  return out;
}

/**
 * A cookie source can be many things depending on where it is called:
 * a Web `Request`, a Next.js `NextRequest`, the `cookies()` store from
 * `next/headers`, a Node `IncomingMessage`, or a plain name→value map.
 */
export type CookieSource =
  | Request
  | { cookies: { get(name: string): { value: string } | undefined } } // NextRequest
  | { cookies: Record<string, string> } // Pages Router req.cookies
  | { get(name: string): { value: string } | string | undefined } // next/headers store
  | { headers: { cookie?: string } } // Node IncomingMessage
  | Record<string, string>
  | string;

/** Read a single cookie value from any of the supported cookie sources. */
export function readCookie(source: CookieSource | undefined, name: string): string | undefined {
  if (!source) return undefined;

  if (typeof source === 'string') {
    return parseCookieHeader(source)[name];
  }

  const anySource = source as Record<string, unknown>;

  // Web Request / anything exposing a Headers object.
  if (anySource.headers && typeof (anySource.headers as Headers).get === 'function') {
    return parseCookieHeader((anySource.headers as Headers).get('cookie'))[name];
  }

  // NextRequest (.cookies.get) or Pages req.cookies (plain object).
  const cookies = anySource.cookies as
    | { get?: (n: string) => { value: string } | undefined }
    | Record<string, string>
    | undefined;
  if (cookies) {
    if (typeof (cookies as { get?: unknown }).get === 'function') {
      return (cookies as { get: (n: string) => { value: string } | undefined }).get(name)?.value;
    }
    return (cookies as Record<string, string>)[name];
  }

  // next/headers cookie store (.get returns { value }).
  if (typeof anySource.get === 'function') {
    const entry = (anySource.get as (n: string) => { value: string } | string | undefined)(name);
    return typeof entry === 'string' ? entry : entry?.value;
  }

  // Node IncomingMessage with a raw cookie header.
  const nodeHeaders = anySource.headers as { cookie?: string } | undefined;
  if (nodeHeaders?.cookie) {
    return parseCookieHeader(nodeHeaders.cookie)[name];
  }

  // Plain name→value map.
  if (typeof anySource[name] === 'string') {
    return anySource[name];
  }

  return undefined;
}

/** Decode a base64url string in either the Edge (atob) or Node (Buffer) runtime. */
function decodeBase64Url(value: string): string | null {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  try {
    if (typeof atob !== 'undefined') return atob(normalized);
    const buffer = (globalThis as { Buffer?: { from(d: string, e: string): { toString(e: string): string } } }).Buffer;
    if (buffer) return buffer.from(normalized, 'base64').toString('utf8');
  } catch {
    return null;
  }
  return null;
}

/**
 * Returns true when a JWT is missing, malformed, or past its `exp` claim
 * (with a 5s buffer). The signature is NOT verified — Next.js does not hold the
 * signing secret; authoritative validation happens via `/api/auth/me`.
 */
export function isJwtExpired(token: string | undefined): boolean {
  if (!token) return true;
  const payload = token.split('.')[1];
  if (!payload) return true;
  const json = decodeBase64Url(payload);
  if (!json) return true;
  try {
    const claims = JSON.parse(json) as { exp?: number };
    if (typeof claims.exp !== 'number') return false;
    return Date.now() >= claims.exp * 1000 - 5000;
  } catch {
    return true;
  }
}
