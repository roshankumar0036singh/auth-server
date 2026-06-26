/**
 * Template generators for create-auth-app. Each returns a list of files (with
 * the chosen server URL / client ID injected) plus the post-scaffold steps.
 *
 * Generated file bodies avoid `${...}` so they can live inside these template
 * literals without escaping; dynamic values are injected via `${opts.*}`.
 */

const SDK_VERSION = '^1.1.0';

/** @typedef {{ packageName: string, serverUrl: string, clientId: string }} Opts */

const gitignore = `node_modules
dist
.next
.env
.env.local
*.log
`;

/** @param {Opts} opts */
export function node(opts) {
  return {
    install: 'npm install',
    dev: 'npm start',
    steps: [
      'npm install',
      'Edit .env with your AUTH_EMAIL / AUTH_PASSWORD',
      'npm start',
    ],
    files: [
      {
        path: 'package.json',
        contents: JSON.stringify(
          {
            name: opts.packageName,
            private: true,
            type: 'module',
            engines: { node: '>=20.6.0' },
            scripts: { start: 'node --env-file=.env index.mjs' },
            dependencies: { '@authserver/client': SDK_VERSION },
          },
          null,
          2,
        ) + '\n',
      },
      {
        path: '.env',
        contents: `AUTH_SERVER_URL=${opts.serverUrl}
AUTH_CLIENT_ID=${opts.clientId}
AUTH_EMAIL=you@example.com
AUTH_PASSWORD=a-strong-password
`,
      },
      {
        path: 'index.mjs',
        contents: `import { AuthClient, AuthError } from '@authserver/client';

const auth = new AuthClient({
  serverUrl: process.env.AUTH_SERVER_URL,
  clientId: process.env.AUTH_CLIENT_ID,
});

try {
  await auth.login(process.env.AUTH_EMAIL, process.env.AUTH_PASSWORD);
  const user = await auth.getUser();
  console.log('Signed in as ' + (user.firstName || user.email));
  await auth.logout();
} catch (error) {
  if (error instanceof AuthError) {
    console.error('[' + error.code + '] ' + error.message);
    process.exit(1);
  }
  throw error;
}
`,
      },
      { path: '.gitignore', contents: gitignore },
      {
        path: 'README.md',
        contents: `# ${opts.packageName}

A Node.js app wired up with [\`@authserver/client\`](https://www.npmjs.com/package/@authserver/client).

\`\`\`bash
npm install
# set AUTH_EMAIL / AUTH_PASSWORD in .env
npm start
\`\`\`
`,
      },
    ],
  };
}

/** @param {Opts} opts */
export function react(opts) {
  return {
    install: 'npm install',
    dev: 'npm run dev',
    steps: ['npm install', 'npm run dev', 'Open http://localhost:5173'],
    files: [
      {
        path: 'package.json',
        contents: JSON.stringify(
          {
            name: opts.packageName,
            private: true,
            type: 'module',
            scripts: { dev: 'vite', build: 'tsc && vite build', preview: 'vite preview' },
            dependencies: {
              '@authserver/client': SDK_VERSION,
              react: '^18.3.1',
              'react-dom': '^18.3.1',
            },
            devDependencies: {
              '@types/react': '^18.3.3',
              '@types/react-dom': '^18.3.0',
              '@vitejs/plugin-react': '^4.3.1',
              typescript: '^5.4.5',
              vite: '^5.3.0',
            },
          },
          null,
          2,
        ) + '\n',
      },
      {
        path: '.env',
        contents: `VITE_AUTH_SERVER_URL=${opts.serverUrl}
VITE_AUTH_CLIENT_ID=${opts.clientId}
`,
      },
      {
        path: 'index.html',
        contents: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${opts.packageName}</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
`,
      },
      {
        path: 'vite.config.ts',
        contents: `import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({ plugins: [react()], server: { port: 5173 } });
`,
      },
      {
        path: 'tsconfig.json',
        contents: JSON.stringify(
          {
            compilerOptions: {
              target: 'ES2020',
              lib: ['ES2020', 'DOM', 'DOM.Iterable'],
              module: 'ESNext',
              moduleResolution: 'bundler',
              jsx: 'react-jsx',
              strict: true,
              skipLibCheck: true,
              noEmit: true,
              types: ['vite/client'],
            },
            include: ['src'],
          },
          null,
          2,
        ) + '\n',
      },
      {
        path: 'src/auth.ts',
        contents: `import { AuthClient } from '@authserver/client';

export const authClient = new AuthClient({
  serverUrl: import.meta.env.VITE_AUTH_SERVER_URL,
  clientId: import.meta.env.VITE_AUTH_CLIENT_ID,
  storage: 'localStorage',
});
`,
      },
      {
        path: 'src/main.tsx',
        contents: `import React from 'react';
import { createRoot } from 'react-dom/client';
import { AuthProvider } from '@authserver/client/react';
import { authClient } from './auth';
import { App } from './App';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider client={authClient}>
      <App />
    </AuthProvider>
  </React.StrictMode>,
);
`,
      },
      {
        path: 'src/App.tsx',
        contents: `import { useState } from 'react';
import { useAuth } from '@authserver/client/react';

export function App() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  if (isLoading) return <p>Loading…</p>;

  if (!isAuthenticated) {
    return (
      <form onSubmit={async (e) => {
        e.preventDefault();
        try {
          await login(email, password);
        } catch (err) {
          alert('Login failed: ' + (err instanceof Error ? err.message : String(err)));
        }
      }}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
        <input value={password} type="password" onChange={(e) => setPassword(e.target.value)} placeholder="password" />
        <button type="submit">Sign in</button>
      </form>
    );
  }

  return (
    <section>
      <p>Signed in as {user?.firstName ?? user?.email}</p>
      <button onClick={() => void logout()}>Sign out</button>
    </section>
  );
}
`,
      },
      { path: '.gitignore', contents: gitignore },
    ],
  };
}

/** @param {Opts} opts */
export function next(opts) {
  return {
    install: 'npm install',
    dev: 'npm run dev',
    steps: ['npm install', 'npm run dev', 'Open http://localhost:3000'],
    files: [
      {
        path: 'package.json',
        contents: JSON.stringify(
          {
            name: opts.packageName,
            private: true,
            scripts: { dev: 'next dev', build: 'next build', start: 'next start' },
            dependencies: {
              '@authserver/client': SDK_VERSION,
              next: '^15.0.0',
              react: '^18.3.1',
              'react-dom': '^18.3.1',
            },
            devDependencies: {
              '@types/node': '^20.0.0',
              '@types/react': '^18.3.3',
              typescript: '^5.4.5',
            },
          },
          null,
          2,
        ) + '\n',
      },
      {
        path: '.env.local',
        contents: `AUTH_SERVER_URL=${opts.serverUrl}
AUTH_CLIENT_ID=${opts.clientId}
`,
      },
      {
        path: 'tsconfig.json',
        contents: JSON.stringify(
          {
            compilerOptions: {
              target: 'ES2020',
              lib: ['dom', 'dom.iterable', 'esnext'],
              module: 'esnext',
              moduleResolution: 'bundler',
              jsx: 'preserve',
              strict: true,
              skipLibCheck: true,
              noEmit: true,
              esModuleInterop: true,
              resolveJsonModule: true,
              incremental: true,
              plugins: [{ name: 'next' }],
              paths: { '@/*': ['./*'] },
            },
            include: ['next-env.d.ts', '**/*.ts', '**/*.tsx', '.next/types/**/*.ts'],
            exclude: ['node_modules'],
          },
          null,
          2,
        ) + '\n',
      },
      {
        path: 'lib/auth.ts',
        contents: `import { createAuthServer } from '@authserver/client/nextjs';

export const authServer = createAuthServer({
  serverUrl: process.env.AUTH_SERVER_URL!,
  clientId: process.env.AUTH_CLIENT_ID!,
  afterLoginPath: '/dashboard',
});
`,
      },
      {
        path: 'app/api/auth/[...authserver]/route.ts',
        contents: `import { authServer } from '@/lib/auth';

export const { GET, POST } = authServer.handlers;
`,
      },
      {
        path: 'middleware.ts',
        contents: `import { NextResponse } from 'next/server';
import { authServer } from '@/lib/auth';

export function middleware(req: Request) {
  return authServer.middleware({ publicPaths: ['/', '/login'] })(req) ?? NextResponse.next();
}

export const config = { matcher: ['/dashboard/:path*'] };
`,
      },
      {
        path: 'app/layout.tsx',
        contents: `export const metadata = { title: '${opts.packageName}' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
`,
      },
      {
        path: 'app/page.tsx',
        contents: `'use client';

import { useState } from 'react';

export default function Home() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function signIn(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (res.ok) window.location.href = '/dashboard';
    else setError('Login failed');
  }

  return (
    <main style={{ fontFamily: 'sans-serif', maxWidth: 420, margin: '4rem auto' }}>
      <h1>Sign in</h1>
      <form onSubmit={signIn} style={{ display: 'grid', gap: 8 }}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
        <input value={password} type="password" onChange={(e) => setPassword(e.target.value)} placeholder="password" />
        <button type="submit">Sign in</button>
        {error && <p style={{ color: 'crimson' }}>{error}</p>}
      </form>
    </main>
  );
}
`,
      },
      {
        path: 'app/dashboard/page.tsx',
        contents: `import { cookies } from 'next/headers';
import { authServer } from '@/lib/auth';

export default async function Dashboard() {
  const session = await authServer.getSession(await cookies());
  if (!session) return <p style={{ fontFamily: 'sans-serif' }}><a href="/">Sign in</a></p>;

  return (
    <main style={{ fontFamily: 'sans-serif', maxWidth: 420, margin: '4rem auto' }}>
      <p>Welcome, {session.user.firstName ?? session.user.email}</p>
      <form action="/api/auth/logout" method="post"><button>Sign out</button></form>
    </main>
  );
}
`,
      },
      { path: '.gitignore', contents: gitignore + '.next\n' },
    ],
  };
}

export const templates = { node, react, next };
export const templateNames = Object.keys(templates);
