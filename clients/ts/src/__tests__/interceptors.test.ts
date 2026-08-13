import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createFetchInterceptor } from '../interceptors';
import { AuthClient, AuthError } from '../AuthClient';

const okResponse = (body = '{}', status = 200) =>
  new Response(body, { status, headers: { 'Content-Type': 'application/json' } });

const createClient = () =>
  new AuthClient({ serverUrl: 'https://auth.example.com', clientId: 'test-client' });

describe('createFetchInterceptor', () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it('injects the Authorization header when a token is present', async () => {
    const client = createClient() as unknown as { getAccessToken: () => string | null };
    (client as unknown as { getAccessToken: () => string | null }).getAccessToken = () => 'abc';
    const fetchMock = vi.fn(async (_input: unknown, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get('Authorization')).toBe('Bearer abc');
      return okResponse();
    });

    const interceptor = createFetchInterceptor(client as unknown as AuthClient, fetchMock as typeof fetch);
    const res = await interceptor('https://auth.example.com/api/test');
    expect(res.ok).toBe(true);
  });

  it('retries network failures with exponential backoff and succeeds', async () => {
    const client = createClient();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValue(okResponse());

    const interceptor = createFetchInterceptor(client, fetchMock as unknown as typeof fetch, {
      retries: 3,
      retryDelay: 5,
    });
    const res = await interceptor('https://auth.example.com/api/test');
    expect(res.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects with NETWORK_ERROR and fires network:error once retries are exhausted', async () => {
    const onNetworkError = vi.fn();
    const client = new AuthClient({
      serverUrl: 'https://auth.example.com',
      clientId: 'test-client',
      onNetworkError,
    });
    const eventSpy = vi.fn();
    client.on('network:error', eventSpy);

    const fetchMock = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    const interceptor = createFetchInterceptor(client, fetchMock as unknown as typeof fetch, {
      retries: 1,
      retryDelay: 1,
    });

    await expect(interceptor('https://auth.example.com/api/test')).rejects.toThrow(AuthError);
    const err = await interceptor('https://auth.example.com/api/test').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).code).toBe('NETWORK_ERROR');
    expect((err as AuthError).status).toBe(0);

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(onNetworkError).toHaveBeenCalledTimes(2);
    expect(eventSpy).toHaveBeenCalledTimes(2);
    expect(eventSpy.mock.calls[0][0]).toBeInstanceOf(AuthError);
  });

  it('does not retry on HTTP error responses', async () => {
    const client = createClient();
    const fetchMock = vi.fn().mockResolvedValue(okResponse('{}', 500));
    const interceptor = createFetchInterceptor(client, fetchMock as unknown as typeof fetch, {
      retries: 3,
      retryDelay: 1,
    });

    const res = await interceptor('https://auth.example.com/api/test');
    expect(res.status).toBe(500);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
