import { useState } from 'react';
import { AuthError } from '@authserver/client';
import { useAuth } from '@authserver/client/react';

export function App() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  if (isLoading) return <p style={{ fontFamily: 'sans-serif' }}>Loading session…</p>;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof AuthError ? `${err.code}: ${err.message}` : 'Login failed');
    }
  }

  return (
    <main style={{ fontFamily: 'sans-serif', maxWidth: 420, margin: '4rem auto' }}>
      <h1>@authserver/client · React example</h1>

      {isAuthenticated ? (
        <section>
          <p>
            Signed in as <strong>{user?.firstName ?? user?.email}</strong>
          </p>
          <button type="button" onClick={() => logout()}>
            Sign out
          </button>
        </section>
      ) : (
        <form onSubmit={onSubmit} style={{ display: 'grid', gap: 8 }}>
          <input
            type="email"
            placeholder="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <input
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <button type="submit">Sign in</button>
          {error && <p style={{ color: 'crimson' }}>{error}</p>}
        </form>
      )}
    </main>
  );
}
