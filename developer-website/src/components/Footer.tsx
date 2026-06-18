import { LINKS } from "@/lib/links";

export function Footer() {
  return (
    <footer className="relative mt-auto border-t border-zinc-800/80 bg-black/40 backdrop-blur-sm">
      <div className="mx-auto flex max-w-5xl flex-col gap-4 px-6 py-8 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-sm leading-relaxed text-zinc-500">
          Auth Server — open-source authentication microservice. MIT License.
        </p>
        <div className="flex flex-wrap gap-5">
          <a
            href={LINKS.github}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-zinc-300 opacity-80 transition-opacity hover:opacity-100"
          >
            GitHub
          </a>
          <a
            href={LINKS.swagger}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-zinc-300 opacity-80 transition-opacity hover:opacity-100"
          >
            API Docs
          </a>
          <a
            href={LINKS.npm}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-zinc-300 opacity-80 transition-opacity hover:opacity-100"
          >
            npm SDK
          </a>
        </div>
      </div>
    </footer>
  );
}
