import { GitHubIcon } from "@/components/NavIcons";
import { ArrowRightIcon } from "@/components/landing/icons";
import { LINKS } from "@/lib/links";

export function OpenSource() {
  return (
    <section className="pb-16 sm:pb-20">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-start justify-between gap-6 rounded-2xl border border-zinc-200/80 bg-gradient-to-br from-zinc-50 via-white to-accent/5 p-8 sm:flex-row sm:items-center dark:border-zinc-800/80 dark:from-zinc-900/80 dark:via-zinc-950 dark:to-accent/10">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
              Open source · MIT License
            </h2>
            <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
              Fork it, deploy it, contribute on GitHub.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <a
              href={LINKS.github}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-zinc-800 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-white"
            >
              <GitHubIcon className="h-4 w-4" />
              Star on GitHub
              <ArrowRightIcon />
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
