import { inject, Plugin, App, reactive, readonly, computed } from 'vue';
import { AuthClient, Session, AuthClientConfig } from '../index';

const AuthSymbol = Symbol('AuthClient');
const SessionSymbol = Symbol('AuthSession');

export const createAuth = (config: AuthClientConfig): Plugin => {
  return {
    install(app: App) {
      const client = new AuthClient(config);
      const sessionState = reactive<{ session: Session | null; isLoading: boolean }>({ 
        session: null, 
        isLoading: true 
      });

      client.ready.finally(() => {
        sessionState.isLoading = false;
      });

      client.on('session', (newSession) => {
        sessionState.session = newSession;
      });

      app.provide(AuthSymbol, client);
      app.provide(SessionSymbol, readonly(sessionState));
    }
  };
};

export const useAuth = () => {
  const client = inject<AuthClient>(AuthSymbol);
  const sessionState = inject<{ session: Session | null; isLoading: boolean }>(SessionSymbol);
  
  if (!client || !sessionState) {
    throw new Error('useAuth must be used within a Vue app installed with createAuth plugin');
  }
  
  return {
    client,
    session: computed(() => sessionState.session),
    isAuthenticated: computed(() => !!sessionState.session),
    isLoading: computed(() => sessionState.isLoading)
  };
};
