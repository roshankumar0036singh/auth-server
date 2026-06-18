"use client";


// s

import Image from "next/image";
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  DocsIcon,
  FeaturesIcon,
  GitHubIcon,
  SwaggerIcon,
} from "@/components/NavIcons";
import { LINKS } from "@/lib/links";

const nav = [
  {
    href: "/#features",
    label: "Features",
    icon: FeaturesIcon,
  },
  {
    href: "/docs",
    label: "Docs",
    icon: DocsIcon,
  },
  {
    href: LINKS.swagger,
    label: "API",
    external: true,
    icon: SwaggerIcon,
  },
  {
    href: LINKS.github,
    label: "GitHub",
    external: true,
    icon: GitHubIcon,
  },
] as const;

const navLinkClass =
  "relative inline-flex items-center gap-1.5 py-1 text-sm text-zinc-400 transition-colors after:absolute after:bottom-0 after:left-0 after:h-0.5 after:w-full after:origin-left after:scale-x-0 after:bg-accent after:transition-transform after:duration-200 hover:text-zinc-100 hover:after:scale-x-100";

const mobileNavLinkClass =
  "relative flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium text-zinc-300 transition-colors after:absolute after:bottom-1.5 after:left-3 after:right-3 after:h-0.5 after:origin-left after:scale-x-0 after:bg-accent after:transition-transform after:duration-200 hover:bg-zinc-800 hover:after:scale-x-100";

function NavLink({
  item,
  onNavigate,
  className,
}: {
  item: (typeof nav)[number];
  onNavigate?: () => void;
  className: string;
}) {
  const Icon = item.icon;
  const content = (
    <>
      <Icon className="h-4 w-4 shrink-0" />
      <span>{item.label}</span>
    </>
  );

  if ("external" in item && item.external) {
    return (
      <a
        href={item.href}
        target="_blank"
        rel="noopener noreferrer"
        className={className}
        onClick={onNavigate}
      >
        {content}
      </a>
    );
  }

  return (
    <Link href={item.href} className={className} onClick={onNavigate}>
      {content}
    </Link>
  );
}

export function Header() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const closeMenu = () => setOpen(false);

  return (
    <header className="fixed inset-x-0 top-0 z-50 px-4 pt-4 sm:px-6 md:px-8 lg:px-10">
      <div className="mx-auto w-full max-w-5xl overflow-hidden rounded-2xl border border-zinc-800/70 bg-black/80 shadow-[0_8px_32px_rgba(0,0,0,0.5)] backdrop-blur-xl">
        <nav
          aria-label="Main"
          className="flex items-center justify-between gap-4 px-4 py-2.5 sm:px-6 sm:py-3"
        >
          <Link
            href="/"
            className="group flex shrink-0 items-center gap-3"
            onClick={closeMenu}
          >
            <div className="relative h-9 w-9 shrink-0 overflow-hidden rounded-lg ring-1 ring-zinc-700">
              <Image
                src="/logo.png"
                alt=""
                fill
                sizes="36px"
                className="object-cover object-[58%_50%] scale-[2.2]"
                priority
              />
            </div>
            <span
              className={`${navLinkClass} text-base font-bold tracking-tight text-zinc-100 after:bg-accent`}
            >
              Auth Server
            </span>
          </Link>

          <div className="hidden items-center gap-7 md:flex">
            {nav.map((item) => (
              <NavLink key={item.label} item={item} className={navLinkClass} />
            ))}
          </div>

          <div className="flex items-center gap-2">
            <Link
              href="/docs"
              className="hidden items-center justify-center rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-hover md:inline-flex"
            >
              Get started
            </Link>

            <button
              type="button"
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-zinc-200 text-zinc-700 transition-colors hover:bg-zinc-100 md:hidden dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-800"
              aria-label={open ? "Close menu" : "Open menu"}
              aria-expanded={open}
              aria-controls="mobile-menu"
              onClick={() => setOpen((prev) => !prev)}
            >
              {open ? (
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  aria-hidden
                >
                  <path d="M18 6 6 18M6 6l12 12" />
                </svg>
              ) : (
                <svg
                  width="20"
                  height="20"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  aria-hidden
                >
                  <path d="M4 7h16M4 12h16M4 17h16" />
                </svg>
              )}
            </button>
          </div>
        </nav>

        <div
          id="mobile-menu"
          className={`grid border-t border-zinc-800/70 transition-[grid-template-rows,opacity] duration-200 md:hidden ${
            open
              ? "grid-rows-[1fr] opacity-100"
              : "grid-rows-[0fr] opacity-0"
          }`}
          aria-hidden={!open}
        >
          <div className="overflow-hidden">
            <div className="flex flex-col gap-1 px-4 py-3 sm:px-6">
              {nav.map((item) => (
                <NavLink
                  key={item.label}
                  item={item}
                  onNavigate={closeMenu}
                  className={mobileNavLinkClass}
                />
              ))}
              <Link
                href="/docs"
                onClick={closeMenu}
                className="mt-2 inline-flex items-center justify-center rounded-xl bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
              >
                Get started
              </Link>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
