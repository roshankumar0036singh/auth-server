import Link from "next/link";
import { DocsIcon, SwaggerIcon } from "@/components/NavIcons";
import { ExternalLinkIcon } from "@/components/landing/icons";
import { LINKS } from "@/lib/links";

const resources = [
  {
    title: "API reference",
    description: "Swagger UI",
    href: LINKS.swagger,
    external: true,
    icon: SwaggerIcon,
  },
  {
    title: "TypeScript SDK",
    description: "@authserver/client",
    href: LINKS.npm,
    external: true,
    icon: null,
    label: "npm",
  },
  {
    title: "Quick start",
    description: "Run with Docker",
    href: "/docs",
    external: false,
    icon: DocsIcon,
  },
] as const;

export function Resources() {
  return (
    <section className="py-16 sm:py-20">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <h2 className="text-2xl font-bold tracking-tight text-zinc-50">
          Resources
        </h2>

        <div className="mt-8 grid gap-4 sm:grid-cols-3">
          {resources.map((resource) => {
            const Icon = resource.icon;
            const content = (
              <>
                <div className="flex items-start justify-between gap-3">
                  <div className="inline-flex rounded-xl border border-zinc-700 bg-zinc-800/50 p-2 text-zinc-200">
                    {Icon ? (
                      <Icon className="h-5 w-5" />
                    ) : (
                      <span className="px-0.5 font-mono text-xs font-semibold">
                        {resource.label}
                      </span>
                    )}
                  </div>
                  {resource.external && (
                    <ExternalLinkIcon className="shrink-0 text-zinc-400" />
                  )}
                </div>
                <h3 className="mt-3 font-semibold text-zinc-100">
                  {resource.title}
                </h3>
                <p className="mt-0.5 text-sm text-zinc-400">
                  {resource.description}
                </p>
              </>
            );

            const className =
              "rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5 transition-colors hover:border-accent/30";

            if (resource.external) {
              return (
                <a
                  key={resource.title}
                  href={resource.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={className}
                >
                  {content}
                </a>
              );
            }

            return (
              <Link key={resource.title} href={resource.href} className={className}>
                {content}
              </Link>
            );
          })}
        </div>
      </div>
    </section>
  );
}
