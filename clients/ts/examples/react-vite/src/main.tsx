import React from 'react';
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
