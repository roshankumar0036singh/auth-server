import type { Metadata } from "next";
import { LINKS } from "@/lib/links";

export const metadata: Metadata = {
  title: "Docs",
};

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
        Getting started
      </h1>
      <p className="mt-4 text-lg leading-relaxed text-zinc-600 dark:text-zinc-400">
        Run Auth Server locally in a few minutes with Docker.
      </p>

      <div className="mt-12 space-y-10">
        <section>
          <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
            1. Clone and configure
          </h2>
          <pre className="mt-4 overflow-x-auto rounded-xl border border-zinc-200 bg-zinc-950 p-4 font-mono text-sm leading-relaxed text-zinc-100 dark:border-zinc-800">
            {`git clone https://github.com/roshankumar0036singh/auth-server.git
cd auth-server
cp .env.example .env`}
          </pre>
        </section>

        <section>
          <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
            2. Start with Docker
          </h2>
          <pre className="mt-4 overflow-x-auto rounded-xl border border-zinc-200 bg-zinc-950 p-4 font-mono text-sm leading-relaxed text-zinc-100 dark:border-zinc-800">
            docker compose up -d
          </pre>
          <p className="mt-3 text-sm text-zinc-600 dark:text-zinc-400">
            Server runs at{" "}
            <code className="rounded bg-zinc-200 px-1.5 py-0.5 font-mono text-xs dark:bg-zinc-800">
              http://localhost:8080
            </code>
            . API docs at{" "}
            <code className="rounded bg-zinc-200 px-1.5 py-0.5 font-mono text-xs dark:bg-zinc-800">
              /swagger/
            </code>
            .
          </p>
        </section>

        <section>
          <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">
            3. Use in your app
          </h2>
          <pre className="mt-4 overflow-x-auto rounded-xl border border-zinc-200 bg-zinc-950 p-4 font-mono text-sm leading-relaxed text-zinc-100 dark:border-zinc-800">
            {`npm install @authserver/client

# or scaffold a new app
npm create auth-app@latest my-app`}
          </pre>
        </section>

        <section className="rounded-xl border border-zinc-200 bg-white p-6 dark:border-zinc-800 dark:bg-zinc-900/50">
          <h2 className="font-semibold text-zinc-900 dark:text-zinc-100">
            Next steps
          </h2>
          <ul className="mt-4 space-y-2 text-sm text-zinc-600 dark:text-zinc-400">
            <li>
              <a
                href={LINKS.swagger}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline"
              >
                Explore the API
              </a>
            </li>
            <li>
              <a
                href={LINKS.npm}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline"
              >
                Read the TypeScript SDK docs
              </a>
            </li>
            <li>
              <a
                href={LINKS.github}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline"
              >
                View the source on GitHub
              </a>
            </li>
          </ul>
        </section>
      </div>
    </div>
  );
}
