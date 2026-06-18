const layers = [
  "HTTP handlers",
  "Services",
  "Repositories",
  "Infrastructure",
] as const;

export function Architecture() {
  return (
    <section className="border-y border-zinc-800/80 py-16 sm:py-20">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <div className="grid items-center gap-8 lg:grid-cols-2 lg:gap-12">
          <div>
            <h2 className="text-2xl font-bold tracking-tight text-zinc-50">
              Clean architecture in Go
            </h2>
            <p className="mt-3 text-zinc-400">
              Layered, readable, and easy to contribute to.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {layers.map((layer, index) => (
              <div
                key={layer}
                className="flex items-center gap-2.5 rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-3"
              >
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-accent/10 font-mono text-xs font-semibold text-accent">
                  {index + 1}
                </span>
                <span className="text-sm font-medium text-zinc-100">
                  {layer}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
