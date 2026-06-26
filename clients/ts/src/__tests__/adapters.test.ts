import { describe, it, expect, vi } from 'vitest';
import { useAuth as useVueAuth } from '../vue';
import { createAuthStore } from '../svelte';
import { AuthClient } from '../AuthClient';
import * as vue from 'vue';

vi.mock('vue', async () => {
  const actual = await vi.importActual('vue') as any;
  return {
    ...actual,
    inject: vi.fn(),
  };
});

vi.mock('../AuthClient', () => {
  return {
    AuthClient: class {
      sessionCallback: any;
      errorCallback: any;
      ready = Promise.resolve();
      on = vi.fn((event, cb) => {
        if (event === 'session') this.sessionCallback = cb;
        if (event === 'error') this.errorCallback = cb;
      });
      off = vi.fn();
      destroy = vi.fn();
      getUser = vi.fn(() => ({ id: '1' }));
      getAccessToken = vi.fn(() => 'token');
      getRefreshToken = vi.fn(() => 'refresh');
      isAuthenticated = vi.fn(() => true);
      _simulateSession = (session: any) => this.sessionCallback?.(session);
      _simulateError = (error: any) => this.errorCallback?.(error);
    }
  };
});

describe('Vue Adapter', () => {
  it('useAuth exposes correct reactive refs and auth methods', () => {
    const client = new AuthClient({ serverUrl: 'http://localhost' });
    const sessionState = { session: { id: '1' }, isLoading: true };
    
    vi.mocked(vue.inject).mockImplementation((sym: any) => {
      if (sym.toString() === 'Symbol(AuthClient)') return client;
      if (sym.toString() === 'Symbol(AuthSession)') return sessionState;
      return null;
    });

    const auth = useVueAuth();
    
    expect(auth.isLoading.value).toBe(true);
    expect(auth.isAuthenticated.value).toBe(true);
    expect(auth.session.value).toEqual({ id: '1' });
  });
});

describe('Svelte Adapter', () => {
  it('createAuthStore returns a readable store', () => {
    const store = createAuthStore({ serverUrl: 'http://localhost' });
    
    let state: any;
    const unsubscribe = store.subscribe((s: any) => {
      state = s;
    });
    
    expect(state).toBeDefined();
    expect(state.isLoading).toBe(true); // initial state
    
    // Simulate session event
    (store.client as any)._simulateSession({ user: { id: '3' }, accessToken: 'token' });
    expect(state.session).toEqual({ user: { id: '3' }, accessToken: 'token' });
    
    unsubscribe();
  });
});
