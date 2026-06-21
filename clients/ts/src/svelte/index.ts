import { writable, Readable } from 'svelte/store';
import { AuthClient, Session, AuthClientConfig } from '../index';

export interface SvelteAuthStore extends Readable<Session | null> {
  client: AuthClient;
}

export function createAuthStore(config: AuthClientConfig): SvelteAuthStore {
  const client = new AuthClient(config);
  
  // Use a sensible default of null for initial load
  const { subscribe, set } = writable<Session | null>(null);

  // When the session changes in AuthClient, update the svelte store
  client.on('session', (session) => {
    set(session);
  });

  return {
    subscribe,
    client
  };
}
