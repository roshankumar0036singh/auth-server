import { AuthClient, AuthError } from './AuthClient';

/**
 * Options for the fetch interceptor's network-failure handling.
 */
export interface FetchInterceptorOptions {
  /** Max retry attempts on network-level failures (TypeError from fetch). Default 2. */
  retries?: number;
  /** Initial backoff delay in ms before the first retry. Doubles per attempt. Default 1000. */
  retryDelay?: number;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Creates a fetch wrapper that automatically injects the access token and
 * handles automatic token refresh on 401 Unauthorized responses.
 *
 * Network-level failures (offline, unreachable server) are retried with
 * exponential backoff; once retries are exhausted the request rejects with a
 * `NETWORK_ERROR` AuthError and `AuthClient.reportNetworkError` is fired so
 * the UI can react (e.g. show an offline banner).
 *
 * Usage:
 * const customFetch = createFetchInterceptor(authClient, window.fetch);
 * const response = await customFetch('/api/protected');
 */
export const createFetchInterceptor = (
  authClient: AuthClient,
  originalFetch: typeof fetch = fetch,
  options: FetchInterceptorOptions = {},
) => {
  const retries = options.retries ?? 2;
  const retryDelay = options.retryDelay ?? 1000;

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let token = authClient.getAccessToken();
    const headers = new Headers(init?.headers || {});

    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const modifiedInit = { ...init, headers };
    const attemptFetch = async (): Promise<Response> => originalFetch(input, modifiedInit);

    let attempt = 0;
    let lastError: unknown = null;

    while (attempt <= retries) {
      attempt++;
      try {
        const response = await attemptFetch();
        lastError = null;

        // If unauthorized, attempt to refresh the token
        if (response.status === 401 && authClient.getRefreshToken()) {
          try {
            await authClient.refresh();
            token = authClient.getAccessToken();
            if (token) {
              headers.set('Authorization', `Bearer ${token}`);
              modifiedInit.headers = headers;
              // Retry the request with the new token
              return await attemptFetch();
            }
          } catch (err) {
            // Refresh failed, original 401 response will be returned
            // We intentionally swallow the error here because authClient.refresh()
            // already emits error events internally for observability.
            console.warn('Token refresh failed during interceptor retry:', err);
          }
        }

        return response;
      } catch (err) {
        // Network-level failure: fetch only rejects on transport errors
        // (TypeError), so an HTTP error response never lands here.
        lastError = err;
        if (attempt > retries) break;

        const delay = retryDelay * Math.pow(2, attempt - 1);
        await sleep(delay);
      }
    }

    const msg = lastError instanceof Error ? lastError.message : String(lastError);
    const authErr = new AuthError(
      `Network error: unable to reach the server (${msg})`,
      'NETWORK_ERROR',
      0,
    );
    authClient.reportNetworkError(authErr);
    throw authErr;
  };
};
