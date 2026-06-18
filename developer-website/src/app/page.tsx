import Link from "next/link";
import { LINKS } from "@/lib/links";

const features = [
  {
    title: "JWT authentication",
    description: "Access and refresh tokens with secure rotation and revocation.",
  },
  {
    title: "OAuth 2.0 provider",
    description: "Let third-party apps use Sign in with your auth server.",
  },
  {
    title: "Multi-factor auth",
    description: "TOTP support compatible with Google Authenticator.",
  },
  {
    title: "Social login",
    description: "One-click sign-in with Google and GitHub.",
  },
  {
    title: "Role-based access",
    description: "Admin and user roles with protected routes.",
  },
  {
    title: "Production ready",
    description: "Rate limiting, audit logs, Docker, and Redis caching.",
  },
];

export default function Home() {
  return (
    <div>
      {/* Hero */}
      <section className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900/30">
        <div className="mx-auto max-w-5xl px-6 py-20 sm:py-28">
          <p className="mb-4 inline-flex rounded-full border border-accent/20 bg-accent/10 px-3 py-1 text-xs font-medium text-accent">
            Open source · Go · PostgreSQL · Redis
          </p>
          <h1 className="max-w-2xl text-4xl font-bold tracking-tight text-zinc-900 sm:text-5xl dark:text-zinc-50">
            Authentication that your apps can trust
          </h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-zinc-600 dark:text-zinc-400">
            Auth Server is a production-ready microservice for sign-up, login,
            OAuth, MFA, and session management — self-host it or use our demo.
          </p>
          <div className="mt-10 flex flex-wrap gap-4">
            <Link
              href="/docs"
              className="inline-flex items-center justify-center rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
            >
              Get started
            </Link>
            <a
              href={LINKS.github}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center rounded-lg border border-zinc-300 bg-white px-5 py-2.5 text-sm font-semibold text-zinc-900 transition-colors hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
            >
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="scroll-mt-20 py-20">
        <div className="mx-auto max-w-5xl px-6">
          <h2 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
            Everything you need for auth
          </h2>
          <p className="mt-3 max-w-xl text-zinc-600 dark:text-zinc-400">
            Built with clean architecture in Go. Plug in your app with the
            TypeScript SDK or REST API.
          </p>
          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {features.map((feature) => (
              <div
                key={feature.title}
                className="rounded-xl border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900/50"
              >
                <h3 className="font-semibold text-zinc-900 dark:text-zinc-100">
                  {feature.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Quick links */}
      <section className="border-t border-zinc-200 bg-zinc-100/50 py-16 dark:border-zinc-800 dark:bg-zinc-900/20">
        <div className="mx-auto max-w-5xl px-6">
          <h2 className="text-xl font-bold text-zinc-900 dark:text-zinc-50">
            Start building
          </h2>
          <div className="mt-8 grid gap-4 sm:grid-cols-3">
            <a
              href={LINKS.swagger}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-xl border border-zinc-200 bg-white p-5 transition-colors hover:border-accent/40 dark:border-zinc-800 dark:bg-zinc-900/50"
            >
              <p className="font-semibold text-zinc-900 dark:text-zinc-100">
                API reference
              </p>
              <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
                Explore endpoints in Swagger
              </p>
            </a>
            <a
              href={LINKS.npm}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-xl border border-zinc-200 bg-white p-5 transition-colors hover:border-accent/40 dark:border-zinc-800 dark:bg-zinc-900/50"
            >
              <p className="font-semibold text-zinc-900 dark:text-zinc-100">
                TypeScript SDK
              </p>
              <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
                @authserver/client on npm
              </p>
            </a>
            <Link
              href="/docs"
              className="rounded-xl border border-zinc-200 bg-white p-5 transition-colors hover:border-accent/40 dark:border-zinc-800 dark:bg-zinc-900/50"
            >
              <p className="font-semibold text-zinc-900 dark:text-zinc-100">
                Quick start
              </p>
              <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
                Run locally with Docker
              </p>
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
}
