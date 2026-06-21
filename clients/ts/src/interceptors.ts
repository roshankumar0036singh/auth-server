import { AuthClient } from './AuthClient';

/**
 * Creates a fetch wrapper that automatically injects the access token and
 * handles automatic token refresh on 401 Unauthorized responses.
 * 
 * Usage:
 * const customFetch = createFetchInterceptor(authClient, window.fetch);
 * const response = await customFetch('/api/protected');
 */
export const createFetchInterceptor = (authClient: AuthClient, originalFetch: typeof fetch = fetch) => {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    let token = authClient.getAccessToken();
    const headers = new Headers(init?.headers || {});
    
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const modifiedInit = { ...init, headers };
    let response = await originalFetch(input, modifiedInit);

    // If unauthorized, attempt to refresh the token
    if (response.status === 401 && authClient.getRefreshToken()) {
      try {
        await authClient.refresh();
        token = authClient.getAccessToken();
        if (token) {
          headers.set('Authorization', `Bearer ${token}`);
          modifiedInit.headers = headers;
          // Retry the request with the new token
          response = await originalFetch(input, modifiedInit);
        }
      } catch (err) {
        // Refresh failed, original 401 response will be returned
        // We intentionally swallow the error here because authClient.refresh()
        // already emits error events internally for observability.
        console.warn('Token refresh failed during interceptor retry:', err);
      }
    }

    return response;
  };
};
