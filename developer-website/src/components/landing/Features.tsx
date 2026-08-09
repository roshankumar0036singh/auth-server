import type { ComponentType } from "react";
import {
  KeyIcon,
  MfaIcon,
  OAuthIcon,
  ServerIcon,
  ShieldIcon,
  UsersIcon,
} from "@/components/landing/icons";

type Feature = {
  title: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
};

const features: Feature[] = [
  {
    title: "JWT authentication",
    description: "Access & refresh tokens with rotation and revocation.",
    icon: KeyIcon,
  },
  {
    title: "OAuth 2.0 provider",
    description: "Authorization code flow for your apps.",
    icon: OAuthIcon,
  },
  {
    title: "Multi-factor auth",
    description: "TOTP for authenticator apps.",
    icon: MfaIcon,
  },
  {
    title: "Social login",
    description: "Google and GitHub sign-in.",
    icon: UsersIcon,
  },
  {
    title: "Role-based access",
    description: "Admin and user roles with guards.",
    icon: ShieldIcon,
  },
  {
    title: "Production ready",
    description: "Rate limits, audit logs, Docker.",
    icon: ServerIcon,
  },
];

export function Features() {
  return (
    <section id="features" className="scroll-mt-28 py-16 sm:py-20">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <h2 className="text-2xl font-bold tracking-tight text-zinc-50">
          Features
        </h2>

        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <article
                key={feature.title}
                className="group rounded-2xl border border-zinc-800 bg-zinc-900/40 p-5 transition-colors hover:border-accent/30"
              >
                <div className="inline-flex rounded-xl border border-zinc-700 bg-zinc-800/50 p-2 text-accent">
                  <Icon className="h-4 w-4" />
                </div>
                <h3 className="mt-3 font-semibold text-zinc-100">
                  {feature.title}
                </h3>
                <p className="mt-1 text-sm text-zinc-400">
                  {feature.description}
                </p>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
