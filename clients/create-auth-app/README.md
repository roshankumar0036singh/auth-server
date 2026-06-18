# create-auth-app

Scaffold a new app already wired up with [`@authserver/client`](https://www.npmjs.com/package/@authserver/client) — Next.js, React, or Node.js.

```bash
npm create auth-app@latest my-app
# or
npx create-auth-app my-app
```

Run with no flags for an interactive prompt, or pass them directly:

```bash
npm create auth-app@latest my-app -- --template next --client-id abc123
npx create-auth-app my-app -t react
```

## Options

| Flag | Description |
| --- | --- |
| `-t, --template <name>` | `next`, `react`, or `node`. |
| `-s, --server <url>` | Auth server URL. Defaults to the hosted demo server. |
| `--client-id <id>` | Your OAuth client ID. |
| `-y, --yes` | Skip prompts and use defaults for anything not provided. |
| `-h, --help` | Show help. |

## Templates

- **next** — Next.js App Router app using `@authserver/client/nextjs`: httpOnly
  cookie proxy route handler, protected `/dashboard` via middleware, and a login page.
- **react** — React + Vite SPA using `AuthProvider` / `useAuth`.
- **node** — A Node.js script: login → read user → logout.

## Getting a client ID

The default server is the hosted demo server, so a scaffolded app runs as soon as
you add a `clientId`. Follow the
[**Get a Client ID**](https://www.npmjs.com/package/@authserver/client#get-a-client-id)
guide, or self-host the server and pass `--server http://localhost:3000`.
