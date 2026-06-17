// Minimal Node.js example for @authserver/client.
//
//   1. cp ../.env.example ../.env   and fill in the values
//   2. npm install
//   3. npm start
//
// Node 18+ is required (it provides a global fetch). The script logs in with the
// credentials from .env, reads the current user, then logs out.

import { AuthClient, AuthError } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: process.env.AUTH_SERVER_URL ?? 'http://localhost:3000',
  clientId: process.env.AUTH_CLIENT_ID ?? 'local-node-client',
  // Node has no localStorage; 'memory' (the default) is correct here.
});

const email = process.env.AUTH_EMAIL ?? '';
const password = process.env.AUTH_PASSWORD ?? '';

try {
  // Uncomment to create the account the first time you run this:
  // await auth.register(email, password, 'Ada', 'Lovelace');

  const session = await auth.login(email, password);
  console.log('Logged in. Access token starts with:', session.accessToken.slice(0, 16) + '…');

  const user = await auth.getUser();
  console.log(`Current user: ${user.firstName ?? '(no name)'} <${user.email}>`);
  console.log('Email verified:', user.emailVerified, '| MFA enabled:', user.mfaEnabled);

  await auth.logout();
  console.log('Logged out. isAuthenticated:', auth.isAuthenticated());
} catch (error) {
  if (error instanceof AuthError) {
    console.error(`AuthError [${error.code}] (status ${error.status}): ${error.message}`);
    process.exit(1);
  }
  throw error;
}
