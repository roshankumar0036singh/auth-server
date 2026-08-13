import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AdminClient } from '../AdminClient';

const createClient = () => new AdminClient({ serverUrl: 'https://auth.example.com', adminToken: 'tok-1' });

const okResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

const errorResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 401, headers: { 'Content-Type': 'application/json' } });

const usersWireShape = {
  total: 2,
  users: [
    {
      id: 'u1',
      email: 'alice@example.com',
      firstName: 'Alice',
      phone: '+10000000000',
      phoneVerified: true,
      emailVerified: true,
      isActive: true,
      mfaEnabled: false,
      createdAt: '2026-01-01T00:00:00Z',
    },
    {
      id: 'u2',
      email: 'bob@example.com',
      emailVerified: false,
      phoneVerified: false,
      isActive: false,
      mfaEnabled: true,
      createdAt: '2026-02-01T00:00:00Z',
    },
  ],
};

describe('AdminClient', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('GETs /api/admin/users without a query string by default', async () => {
    fetchMock.mockResolvedValueOnce(okResponse({ success: true, message: 'List of users', data: usersWireShape }));
    const client = createClient();
    const result = await client.getUsers();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe('https://auth.example.com/api/admin/users');
    expect((init as RequestInit).method).toBe('GET');
    expect((result as unknown as { success: boolean }).success).toBe(true);
  });

  it('serializes page/limit query parameters', async () => {
    fetchMock.mockResolvedValueOnce(okResponse({ success: true, message: 'List of users', data: usersWireShape }));
    const client = createClient();
    await client.getUsers({ page: 2, limit: 25 });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe('https://auth.example.com/api/admin/users?page=2&limit=25');
  });

  it('strictly types the users + total response shape', async () => {
    fetchMock.mockResolvedValueOnce(okResponse({ success: true, message: 'List of users', data: usersWireShape }));
    const client = createClient();
    const result = await client.getUsers();
    expect(result.data.total).toBe(2);
    expect(result.data.users).toHaveLength(2);
    expect(result.data.users[0].id).toBe('u1');
    expect(result.data.users[0].isActive).toBe(true);
    expect(result.data.users[0].phoneVerified).toBe(true);
    expect(result.data.users[0].emailVerified).toBe(true);
    expect(result.data.users[0].mfaEnabled).toBe(false);
    expect(result.data.users[1].isActive).toBe(false);
    expect(result.data.users[1].mfaEnabled).toBe(true);
  });

  it('listUsers delegates to getUsers (backward compatibility)', async () => {
    fetchMock.mockResolvedValueOnce(okResponse({ success: true, message: 'List of users', data: usersWireShape }));
    const client = createClient();
    const result = await client.listUsers({ page: 1 });
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe('https://auth.example.com/api/admin/users?page=1');
    expect(result.data.total).toBe(2);
  });

  it('throws a typed error on non-OK responses', async () => {
    fetchMock.mockResolvedValueOnce(
      errorResponse({ success: false, error: { code: 'UNAUTHORIZED', message: 'Missing admin token' } }),
    );
    const client = createClient();
    await expect(client.getUsers()).rejects.toThrow('Missing admin token');
  });
});