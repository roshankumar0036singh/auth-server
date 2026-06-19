/**
 * Next.js adapter for `@authserver/client`.
 *
 * Stores tokens in httpOnly cookies on your Next.js app's own domain (a cookie
 * proxy), so Server Components, Route Handlers, middleware, and
 * `getServerSideProps` can all read the session. Works in both the App Router
 * and the Pages Router.
 *
 * @example App Router — app/api/auth/[...authserver]/route.ts
 * ```ts
 * import { createAuthServer } from '@authserver/client/nextjs';
 * export const authServer = createAuthServer({
 *   serverUrl: process.env.AUTH_SERVER_URL!,
 *   clientId: process.env.AUTH_CLIENT_ID!,
 * });
 * export const { GET, POST } = authServer.handlers;
 * ```
 */
import type { User } from '../types';
import {
  CookieSource,
  isJwtExpired,
  readCookie,
  serializeCookie,
  CookieOptions,
} from './internal';

export type { CookieSource } from './internal';

export interface NextAuthConfig {
  /** The auth server origin (no trailing `/api`). */
  serverUrl: string;
  /** Your OAuth client ID. */
  clientId: string;
  /** Cookie name prefix. Access/refresh cookies are `<prefix>_at` / `<prefix>_rt`. Default `'as'`. */
  cookiePrefix?: string;
  /** Mark cookies `Secure`. Defaults to `true` unless `NODE_ENV` is `'development'`. */
  secure?: boolean;
  /** `SameSite` attribute for the session cookies. Default `'lax'`. */
  sameSite?: 'lax' | 'strict' | 'none';
  /** How long (seconds) the cookies persist. Default 7 days. */
  maxAge?: number;
  /** Where middleware redirects unauthenticated users. Default `'/login'`. */
  loginPath?: string;
  /** Where the social-login callback redirects after setting cookies. Default `'/'`. */
  afterLoginPath?: string;
}

export interface ServerSession {
  user: User;
  accessToken: string;
}

interface ResolvedConfig {
  serverUrl: string;
  clientId: string;
  atName: string;
  rtName: string;
  cookieOptions: CookieOptions;
  loginPath: string;
  afterLoginPath: string;
}

function resolveConfig(config: NextAuthConfig): ResolvedConfig {
  if (!config.serverUrl) throw new Error('createAuthServer: serverUrl is required');
  if (!config.clientId) throw new Error('createAuthServer: clientId is required');
  const prefix = config.cookiePrefix ?? 'as';
  const secure =
    config.secure ??
    (globalThis as { process?: { env?: { NODE_ENV?: string } } }).process?.env?.NODE_ENV !== 'development';
  return {
    serverUrl: config.serverUrl.replace(/\/$/, ''),
    clientId: config.clientId,
    atName: `${prefix}_at`,
    rtName: `${prefix}_rt`,
    cookieOptions: {
      httpOnly: true,
      secure,
      sameSite: config.sameSite ?? 'lax',
      path: '/',
      maxAge: config.maxAge ?? 60 * 60 * 24 * 7,
    },
    loginPath: config.loginPath ?? '/login',
    afterLoginPath: config.afterLoginPath ?? '/',
  };
}

function jsonResponse(body: unknown, status: number, cookies: string[] = []): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

export interface AuthServer {
  /** App Router catch-all handlers. `export const { GET, POST } = authServer.handlers`. */
  handlers: {
    GET: (req: Request) => Promise<Response>;
    POST: (req: Request) => Promise<Response>;
  };
  /**
   * Read and validate the current session from any cookie source
   * (a `Request`, `NextRequest`, `cookies()` store, or Pages `ctx.req`).
   * Validates the access token against `/api/auth/me`; returns `null` when there
   * is no valid session. Does not refresh (callers cannot set cookies from a
   * Server Component).
   */
  getSession: (source: CookieSource) => Promise<ServerSession | null>;
  /**
   * Middleware factory. Returns a function that gates protected routes, issuing
   * a redirect `Response` for unauthenticated requests or `undefined` to
   * continue. Compose with `NextResponse.next()`.
   */
  middleware: (options?: MiddlewareOptions) => (req: Request) => Response | undefined;
  /**
   * Build the browser redirect URL for Google social login. Pass the absolute
   * URL of your callback route (e.g. `https://app.com/api/auth/callback`); it
   * must be registered on your OAuth client. The auth server redirects there
   * with tokens, and the `callback` handler converts them to httpOnly cookies.
   */
  googleLoginUrl: (redirectUri?: string) => string;
  /** Build the browser redirect URL for GitHub social login. See {@link googleLoginUrl}. */
  githubLoginUrl: (redirectUri?: string) => string;
  /** Adapt the App Router Web-handler to a Pages Router API route `(req, res)`. */
  toNodeHandler: () => (req: NodeReq, res: NodeRes) => Promise<void>;
}

export interface MiddlewareOptions {
  /** Path prefixes that never require authentication (in addition to `loginPath`). */
  publicPaths?: string[];
  /** Override the redirect target for unauthenticated requests. */
  loginPath?: string;
}

export function createAuthServer(config: NextAuthConfig): AuthServer {
  const cfg = resolveConfig(config);

  async function getSession(source: CookieSource): Promise<ServerSession | null> {
    const accessToken = readCookie(source, cfg.atName);
    if (!accessToken || isJwtExpired(accessToken)) return null;

    let res: Response;
    try {
      res = await fetch(`${cfg.serverUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
    } catch {
      return null;
    }
    if (!res.ok) return null;
    const data = (await res.json().catch(() => null)) as { data?: User } | null;
    if (!data?.data) return null;
    return { user: data.data, accessToken };
  }

  async function handleLogin(req: Request): Promise<Response> {
    try {
      const body = (await req.json().catch(() => ({}))) as { email?: string; password?: string };
      const res = await fetch(`${cfg.serverUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: body.email, password: body.password }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        data?: { accessToken?: string; refreshToken?: string; user?: User };
      };
      if (!res.ok || !data.data?.accessToken) {
        return jsonResponse(data, res.status === 200 ? 502 : res.status);
      }
      return jsonResponse({ user: data.data.user ?? null }, 200, sessionCookies(data.data.accessToken, data.data.refreshToken));
    } catch (err) {
      console.error('Login failed:', err);
      return jsonResponse({ error: 'Network or internal error during login' }, 502);
    }
  }

  async function handleRefresh(req: Request): Promise<Response> {
    const refreshToken = readCookie(req, cfg.rtName);
    if (!refreshToken) return jsonResponse({ error: 'No refresh token' }, 401, [clearCookie(cfg.atName), clearCookie(cfg.rtName)]);
    try {
      const res = await fetch(`${cfg.serverUrl}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      const data = (await res.json().catch(() => ({}))) as {
        data?: { accessToken?: string; refreshToken?: string };
      };
      if (!res.ok || !data.data?.accessToken) {
        return jsonResponse({ error: 'Refresh failed' }, 401, [clearCookie(cfg.atName), clearCookie(cfg.rtName)]);
      }
      return jsonResponse({ ok: true }, 200, sessionCookies(data.data.accessToken, data.data.refreshToken));
    } catch (err) {
      console.error('Refresh failed:', err);
      return jsonResponse({ error: 'Network or internal error during refresh' }, 502, [clearCookie(cfg.atName), clearCookie(cfg.rtName)]);
    }
  }

  async function handleLogout(req: Request): Promise<Response> {
    const refreshToken = readCookie(req, cfg.rtName);
    if (refreshToken) {
      await fetch(`${cfg.serverUrl}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      }).catch(() => undefined);
    }
    return jsonResponse({ ok: true }, 200, [clearCookie(cfg.atName), clearCookie(cfg.rtName)]);
  }

  async function handleSession(req: Request): Promise<Response> {
    const session = await getSession(req);
    return jsonResponse({ user: session?.user ?? null }, 200);
  }

  /**
   * Social-login callback. The auth server redirects here with `access_token`
   * and `refresh_token` query params; we move them into httpOnly cookies and
   * redirect to a clean URL so the tokens never linger in the address bar.
   */
  function handleCallback(req: Request): Response {
    const url = new URL(req.url);
    const accessToken = url.searchParams.get('access_token');
    if (!accessToken) {
      return Response.redirect(new URL(cfg.loginPath, url.origin), 302);
    }
    const refreshToken = url.searchParams.get('refresh_token') ?? undefined;

    // Only allow same-origin path redirects to prevent open-redirect abuse.
    const rawNext = url.searchParams.get('next');
    const next = rawNext && rawNext.startsWith('/') && !rawNext.startsWith('//') ? rawNext : cfg.afterLoginPath;

    const headers = new Headers({ Location: new URL(next, url.origin).toString() });
    for (const cookie of sessionCookies(accessToken, refreshToken)) headers.append('Set-Cookie', cookie);
    return new Response(null, { status: 302, headers });
  }

  function sessionCookies(accessToken: string, refreshToken?: string): string[] {
    const cookies = [serializeCookie(cfg.atName, accessToken, cfg.cookieOptions)];
    if (refreshToken) cookies.push(serializeCookie(cfg.rtName, refreshToken, cfg.cookieOptions));
    return cookies;
  }

  function clearCookie(name: string): string {
    return serializeCookie(name, '', { ...cfg.cookieOptions, maxAge: 0 });
  }

  async function dispatch(req: Request): Promise<Response> {
    const action = new URL(req.url).pathname.split('/').reverse().find(Boolean);
    switch (action) {
      case 'login':
        return req.method === 'POST' ? handleLogin(req) : jsonResponse({ error: 'Method not allowed' }, 405);
      case 'logout':
        return req.method === 'POST' ? handleLogout(req) : jsonResponse({ error: 'Method not allowed' }, 405);
      case 'refresh':
        return req.method === 'POST' ? handleRefresh(req) : jsonResponse({ error: 'Method not allowed' }, 405);
      case 'session':
        return handleSession(req);
      case 'callback':
        return handleCallback(req);
      default:
        return jsonResponse({ error: 'Not found' }, 404);
    }
  }

  function middleware(options: MiddlewareOptions = {}) {
    const loginPath = options.loginPath ?? cfg.loginPath;
    const publicPaths = [loginPath, ...(options.publicPaths ?? [])];
    return (req: Request): Response | undefined => {
      const url = new URL(req.url);
      if (publicPaths.some((p) => url.pathname === p || url.pathname.startsWith(p + '/'))) {
        return undefined;
      }
      const hasAccess = !isJwtExpired(readCookie(req, cfg.atName));
      const hasRefresh = Boolean(readCookie(req, cfg.rtName));
      if (hasAccess || hasRefresh) return undefined;

      const redirectUrl = new URL(loginPath, url.origin);
      redirectUrl.searchParams.set('next', url.pathname + url.search);
      return Response.redirect(redirectUrl, 307);
    };
  }

  function socialLoginUrl(provider: 'google' | 'github', redirectUri?: string): string {
    let url = `${cfg.serverUrl}/api/auth/${provider}/login?client_id=${encodeURIComponent(cfg.clientId)}`;
    if (redirectUri) url += `&redirect_uri=${encodeURIComponent(redirectUri)}`;
    return url;
  }

  function toNodeHandler() {
    return async (req: NodeReq, res: NodeRes): Promise<void> => {
      let host = req.headers.host;
      if (Array.isArray(host)) host = host[0];
      let origin = cfg.serverUrl;
      if (host) {
        const protocol = host.includes('localhost') ? 'http' : 'https';
        origin = `${protocol}://${host}`;
      }
      const request = await nodeRequestToWeb(req, origin);
      const response = await dispatch(request);
      await writeWebResponseToNode(response, res);
    };
  }

  return {
    handlers: { GET: dispatch, POST: dispatch },
    getSession,
    middleware,
    googleLoginUrl: (redirectUri?: string) => socialLoginUrl('google', redirectUri),
    githubLoginUrl: (redirectUri?: string) => socialLoginUrl('github', redirectUri),
    toNodeHandler,
  };
}

// --- Pages Router (Node) bridge -------------------------------------------

interface NodeReq {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  on?(event: string, cb: (chunk?: unknown) => void): void;
}

interface NodeRes {
  statusCode: number;
  setHeader(name: string, value: string | string[]): void;
  end(body?: string): void;
}

async function nodeRequestToWeb(req: NodeReq, origin: string): Promise<Request> {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(key, Array.isArray(value) ? value.join(', ') : value);
  }
  const method = req.method ?? 'GET';
  let body: string | undefined;
  if (method !== 'GET' && method !== 'HEAD') {
    body = await parseNodeBody(req, headers);
  }
  // A base origin is required to construct a URL from a path-only req.url.
  return new Request(new URL(req.url ?? '/', origin), { method, headers, body });
}

async function parseNodeBody(req: NodeReq, headers: Headers): Promise<string | undefined> {
  if (req.body !== undefined && req.body !== null) {
    const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    if (typeof req.body !== 'string') headers.set('content-type', 'application/json');
    return bodyStr;
  }
  if (typeof req.on === 'function') {
    return await readNodeStream(req);
  }
  return undefined;
}

function readNodeStream(req: NodeReq): Promise<string> {
  return new Promise((resolve) => {
    const chunks: string[] = [];
    req.on?.('data', (chunk) => chunks.push(String(chunk)));
    req.on?.('end', () => resolve(chunks.join('')));
    req.on?.('error', () => resolve(''));
  });
}

async function writeWebResponseToNode(response: Response, res: NodeRes): Promise<void> {
  res.statusCode = response.status;
  const setCookies: string[] = [];
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') setCookies.push(value);
    else res.setHeader(key, value);
  });
  if (setCookies.length) res.setHeader('Set-Cookie', setCookies);
  res.end(await response.text());
}
