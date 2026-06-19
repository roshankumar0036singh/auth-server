# Examples

Runnable examples for `@authserver/client`. Each one works against the hosted
server out of the box, or against your own self-hosted server by changing the
environment variables.

Before running either example, follow
[**Get a Client ID**](../README.md#get-a-client-id) to obtain a `clientId`, then
copy the env template:

```bash
cp .env.example .env
# edit .env with your AUTH_SERVER_URL and AUTH_CLIENT_ID
```

| Example | What it shows |
| --- | --- |
| [`node/`](./node) | A plain Node.js script: register (optional), login, read the current user, log out. |
| [`react-vite/`](./react-vite) | A minimal React + Vite app using `AuthProvider` and `useAuth()`. |

The defaults point at the hosted demo server
(`https://auth-server-4nmm.onrender.com`). Treat it as a shared playground —
do not store real credentials there.
