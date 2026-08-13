import { map, Observable, Subject } from 'rxjs';
import { AuthClient } from './AuthClient';
import { AuthEvents, Session } from './types';

/**
 * RxJS integration for `@authserver/client` (issue #175).
 *
 * Bridges the SDK's imperative event emitter to idiomatic RxJS streams so
 * Angular or React-RxJS apps can `combineLatest`, `switchMap` and declaratively
 * react to auth state.
 */
export class AuthState {
  private readonly session$ = new Subject<Session | null>();
  private readonly error$ = new Subject<Error>();
  private readonly disposers: Array<() => void> = [];

  constructor(private readonly client: AuthClient) {
    this.disposers.push(client.on('session', (s) => this.session$.next(s)));
    this.disposers.push(client.on('error', (e) => this.error$.next(e)));
  }

  /** Emits every session change (initial value after `ready`). */
  public session(): Observable<Session | null> {
    return this.session$.asObservable();
  }

  /** Emits SDK errors (refresh failures, network errors, ...). */
  public errors(): Observable<Error> {
    return this.error$.asObservable();
  }

  /** Emits the current session, mapped to its user object. */
  public user(): Observable<Session['user'] | null> {
    return this.session().pipe(map((s) => s?.user ?? null));
  }

  /** Stops all streams. */
  public destroy(): void {
    this.disposers.forEach((d) => d());
    this.session$.complete();
    this.error$.complete();
  }
}

/**
 * Creates an RxJS bridge for the given auth client.
 * @example
 * const rx = createAuthState(authClient);
 * rx.session().pipe(skipWhile((s) => s === null)).subscribe((s) => render(s!.user));
 */
export function createAuthState(client: AuthClient): AuthState {
  return new AuthState(client);
}

export type { AuthEvents };
