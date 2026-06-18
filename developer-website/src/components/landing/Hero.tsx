import Link from "next/link";
import { GitHubIcon } from "@/components/NavIcons";
import { ArrowRightIcon } from "@/components/landing/icons";
import { TAGLINE, TAGLINE_SUB } from "@/lib/copy";
import { LINKS } from "@/lib/links";

const techStack = ["Go", "Gin", "PostgreSQL", "Redis", "Docker"] as const;

const highlights = [
  { label: "License", value: "MIT" },
  { label: "Deploy", value: "Self-host" },
  { label: "API", value: "OpenAPI" },
] as const;

export function Hero() {
  return (
    <section className="landing-hero relative overflow-hidden border-b border-zinc-200/80 dark:border-zinc-800/80">
      <div className="relative mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8 lg:py-24">
        <div className="grid items-center gap-12 lg:grid-cols-[1.05fr_0.95fr] lg:gap-10">
          <div>
            <span className="mb-6 inline-flex rounded-full border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-medium text-accent">
              Open source
            </span>

            <h1 className="max-w-xl text-4xl font-bold tracking-tight text-zinc-900 sm:text-5xl sm:leading-[1.1] dark:text-zinc-50">
              {TAGLINE}
            </h1>

            <p className="mt-5 max-w-md text-lg text-zinc-600 dark:text-zinc-400">
              {TAGLINE_SUB}
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <Link
                href="/docs"
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
              >
                Get started
                <ArrowRightIcon />
              </Link>
              <a
                href={LINKS.github}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-300 bg-white px-5 py-2.5 text-sm font-semibold text-zinc-900 transition-colors hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800"
              >
                <GitHubIcon className="h-4 w-4" />
                GitHub
              </a>
            </div>

            <div className="mt-8 flex flex-wrap gap-2">
              {techStack.map((tech) => (
                <span
                  key={tech}
                  className="rounded-lg border border-zinc-200/80 bg-white/60 px-2.5 py-1 font-mono text-xs text-zinc-600 backdrop-blur-sm dark:border-zinc-700/80 dark:bg-zinc-900/40 dark:text-zinc-300"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>

          <div className="relative">
            <div
              className="absolute -inset-4 rounded-3xl bg-gradient-to-br from-accent/10 via-transparent to-indigo-500/5 blur-2xl"
              aria-hidden
            />
            <div className="relative overflow-hidden rounded-2xl border border-zinc-200/80 bg-white/80 shadow-[0_8px_32px_rgba(0,0,0,0.06)] backdrop-blur-xl dark:border-zinc-800/80 dark:bg-zinc-950/80 dark:shadow-[0_8px_32px_rgba(0,0,0,0.35)]">
              <div className="flex items-center gap-2 border-b border-zinc-200/80 px-4 py-3 dark:border-zinc-800/80">
                <span className="h-2.5 w-2.5 rounded-full bg-zinc-300 dark:bg-zinc-600" />
                <span className="h-2.5 w-2.5 rounded-full bg-zinc-300 dark:bg-zinc-600" />
                <span className="h-2.5 w-2.5 rounded-full bg-zinc-300 dark:bg-zinc-600" />
                <span className="ml-2 font-mono text-xs text-zinc-500 dark:text-zinc-400">
                  quick-start.sh
                </span>
              </div>
              <pre className="overflow-x-auto p-5 font-mono text-[13px] leading-relaxed text-zinc-800 dark:text-zinc-200">
                <code>
                  git clone {LINKS.github}.git
                  {"\n"}
                  cd auth-server && cp .env.example .env
                  {"\n"}
                  docker compose up -d
                </code>
              </pre>
            </div>

            <dl className="mt-6 grid grid-cols-3 gap-3">
              {highlights.map((item) => (
                <div
                  key={item.label}
                  className="rounded-xl border border-zinc-200/80 bg-white/60 px-3 py-3 text-center backdrop-blur-sm dark:border-zinc-800/80 dark:bg-zinc-900/40"
                >
                  <dt className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">
                    {item.label}
                  </dt>
                  <dd className="mt-1 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                    {item.value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </div>
    </section>
  );
}
