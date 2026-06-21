import { writable, Readable } from 'svelte/store';
import { AuthClient, Session, AuthClientConfig } from '../index';

export interface AuthState {
  session: Session | null;
  isLoading: boolean;
  isAuthenticated: boolean;
}

export interface SvelteAuthStore extends Readable<AuthState> {
  client: AuthClient;
}

export function createAuthStore(config: AuthClientConfig): SvelteAuthStore {
  const client = new AuthClient(config);
  
  const { subscribe, update } = writable<AuthState>({
    session: null,
    isLoading: true,
    isAuthenticated: false
  });

  client.ready.finally(() => {
    update(state => ({ ...state, isLoading: false }));
  });

  client.on('session', (session) => {
    update(state => ({ ...state, session, isAuthenticated: !!session }));
  });

  return {
    subscribe,
    client
  };
}
