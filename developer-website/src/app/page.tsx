import { Architecture } from "@/components/landing/Architecture";
import { Features } from "@/components/landing/Features";
import { Hero } from "@/components/landing/Hero";
import { OpenSource } from "@/components/landing/OpenSource";
import { Resources } from "@/components/landing/Resources";

export default function Home() {
  return (
    <>
      <Hero />
      <Features />
      <Architecture />
      <Resources />
      <OpenSource />
    </>
  );
}
