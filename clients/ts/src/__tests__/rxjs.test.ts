import { describe, expect, it, vi } from 'vitest';
import { AuthClient } from '../AuthClient';
import { AuthClientConfig } from '../types';
import { createAuthState } from '../rxjs';
import { Session } from '../types';

function makeClient(config: Partial<AuthClientConfig> = {}): AuthClient {
  return new AuthClient({ serverUrl: 'https://auth.example.com', clientId: 'test', ...config });
}

describe('createAuthState (issue #175)', () => {
  it('emits session events', async () => {
    const client = makeClient();
    const rx = createAuthState(client);
    const seen: Array<Session | null> = [];
    rx.session().subscribe((s) => seen.push(s));
    client['emit']('session', { accessToken: 'a', refreshToken: 'r' });
    client['emit']('session', null);
    expect(seen.some((s) => s !== null && s.accessToken === 'a')).toBe(true);
    expect(seen[seen.length - 1]).toBeNull();
    rx.destroy();
  });

  it('does not emit after destroy', () => {
    const client = makeClient();
    const rx = createAuthState(client);
    const seen: unknown[] = [];
    rx.errors().subscribe((e) => seen.push(e));
    rx.destroy();
    client['emit']('error', new Error('boom'));
    expect(seen).toHaveLength(0);
  });
});
