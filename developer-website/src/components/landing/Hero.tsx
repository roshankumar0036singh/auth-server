import Link from "next/link";
import { GitHubIcon } from "@/components/NavIcons";
import { ArrowRightIcon } from "@/components/landing/icons";
import { Terminal } from "@/components/landing/Terminal";
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
    <section className="landing-hero relative flex min-h-dvh flex-col overflow-hidden border-b border-zinc-800/80">
      <div className="relative mx-auto flex w-full max-w-5xl flex-1 flex-col justify-center px-4 pb-8 pt-24 sm:px-6 sm:pb-10 sm:pt-28 lg:px-8">
        <div className="grid items-center gap-8 lg:grid-cols-[1.05fr_0.95fr] lg:gap-10">
          <div>
            <span className="hero-fade-in mb-5 inline-flex rounded-full border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-medium text-accent">
              Open source
            </span>

            <h1 className="hero-fade-in hero-fade-in-delay-1 max-w-xl text-3xl font-bold tracking-tight text-zinc-50 sm:text-4xl lg:text-5xl lg:leading-[1.1]">
              {TAGLINE}
            </h1>

            <p className="hero-fade-in hero-fade-in-delay-2 mt-4 max-w-md text-base text-zinc-400 sm:text-lg">
              {TAGLINE_SUB}
            </p>

            <div className="hero-fade-in hero-fade-in-delay-3 mt-6 flex flex-wrap gap-3">
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
                className="inline-flex items-center justify-center gap-2 rounded-xl border border-zinc-700 bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-zinc-100 transition-colors hover:bg-zinc-800"
              >
                <GitHubIcon className="h-4 w-4" />
                GitHub
              </a>
            </div>

            <div className="hero-fade-in hero-fade-in-delay-4 mt-6 flex flex-wrap gap-2">
              {techStack.map((tech) => (
                <span
                  key={tech}
                  className="rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-1 font-mono text-xs text-zinc-300"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>

          <div className="hero-fade-in hero-fade-in-delay-2 relative">
            <div
              className="absolute -inset-4 rounded-3xl bg-gradient-to-br from-accent/10 via-transparent to-indigo-500/5 blur-2xl"
              aria-hidden
            />
            <Terminal />

            <dl className="hero-fade-in hero-fade-in-delay-4 mt-4 grid grid-cols-3 gap-3 sm:mt-5">
              {highlights.map((item) => (
                <div
                  key={item.label}
                  className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-3 py-2.5 text-center sm:py-3"
                >
                  <dt className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">
                    {item.label}
                  </dt>
                  <dd className="mt-1 text-sm font-semibold text-zinc-100">
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
