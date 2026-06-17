import { AuthClient } from '@authserver/client';

// Create one client for the whole app, outside React, so re-renders never
// replace it. Values come from .env (see .env.example).
export const authClient = new AuthClient({
  serverUrl: import.meta.env.VITE_AUTH_SERVER_URL ?? 'http://localhost:3000',
  clientId: import.meta.env.VITE_AUTH_CLIENT_ID ?? 'local-client',
  storage: 'localStorage',
});
