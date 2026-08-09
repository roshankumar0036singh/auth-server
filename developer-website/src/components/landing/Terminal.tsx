"use client";

import { useEffect, useState } from "react";
import { LINKS } from "@/lib/links";

const TYPING_MS = 42;
const LINE_PAUSE_MS = 380;
const LOOP_PAUSE_MS = 2800;

const commands = [
  `git clone ${LINKS.github}.git`,
  "cd auth-server && cp .env.example .env",
  "docker compose up -d",
] as const;

function CommandText({ text, active }: { text: string; active?: boolean }) {
  if (!text) return null;

  if (text.startsWith("git")) {
    const prefix = "git clone ";
    if (!text.startsWith(prefix)) {
      return <span className="text-zinc-300">{text}</span>;
    }
    return (
      <>
        <span className="text-zinc-300">{prefix}</span>
        <span className="text-sky-400">{text.slice(prefix.length)}</span>
      </>
    );
  }

  if (text.startsWith("cd")) {
    const andIndex = text.indexOf(" && ");
    if (andIndex === -1) {
      const dir = text.slice(3);
      return (
        <>
          <span className="text-zinc-300">cd </span>
          {dir && <span className="text-amber-300">{dir}</span>}
        </>
      );
    }
    const dir = text.slice(3, andIndex);
    const rest = text.slice(andIndex + 4);
    return (
      <>
        <span className="text-zinc-300">cd </span>
        <span className="text-amber-300">{dir}</span>
        <span className="text-zinc-500"> && </span>
        <span className="text-zinc-300">{rest}</span>
      </>
    );
  }

  return (
    <span className={active ? "text-zinc-100" : "text-zinc-300"}>{text}</span>
  );
}

function CommandLine({
  text,
  active,
  showCursor,
}: {
  text: string;
  active?: boolean;
  showCursor?: boolean;
}) {
  return (
    <div className="flex min-h-[1.625rem] items-start gap-2">
      <span className="shrink-0 select-none text-emerald-400">$</span>
      <span className="min-w-0 flex-1 break-all">
        <CommandText text={text} active={active} />
        {showCursor && <TerminalCursor />}
      </span>
    </div>
  );
}

function TerminalCursor() {
  return (
    <span
      className="terminal-cursor ml-px inline-block h-[1.1em] w-[0.55em] translate-y-[0.12em] bg-emerald-400"
      aria-hidden
    />
  );
}

export function Terminal() {
  const [completedLines, setCompletedLines] = useState<string[]>([]);
  const [lineIndex, setLineIndex] = useState(0);
  const [charIndex, setCharIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [reduceMotion, setReduceMotion] = useState(false);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduceMotion(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  const finished = lineIndex >= commands.length;
  const currentLine =
    reduceMotion || finished ? "" : commands[lineIndex].slice(0, charIndex);

  useEffect(() => {
    if (reduceMotion) {
      setCompletedLines([...commands]);
      setLineIndex(commands.length);
      return;
    }

    if (finished) {
      const loopTimer = window.setTimeout(() => {
        setCompletedLines([]);
        setLineIndex(0);
        setCharIndex(0);
        setIsPaused(false);
      }, LOOP_PAUSE_MS);
      return () => window.clearTimeout(loopTimer);
    }

    if (isPaused) {
      const pauseTimer = window.setTimeout(() => {
        setIsPaused(false);
        setLineIndex((prev) => prev + 1);
        setCharIndex(0);
      }, LINE_PAUSE_MS);
      return () => window.clearTimeout(pauseTimer);
    }

    const line = commands[lineIndex];
    if (charIndex >= line.length) {
      setCompletedLines((prev) => [...prev, line]);
      setIsPaused(true);
      return;
    }

    const typeTimer = window.setTimeout(() => {
      setCharIndex((prev) => prev + 1);
    }, TYPING_MS);
    return () => window.clearTimeout(typeTimer);
  }, [charIndex, finished, isPaused, lineIndex, reduceMotion]);

  return (
    <div className="terminal-window overflow-hidden rounded-2xl border border-zinc-800/90 shadow-[0_8px_32px_rgba(0,0,0,0.35)]">
      <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900/95 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-[#ff5f57]" />
        <span className="h-2.5 w-2.5 rounded-full bg-[#febc2e]" />
        <span className="h-2.5 w-2.5 rounded-full bg-[#28c840]" />
        <span className="ml-2 font-mono text-xs text-zinc-500">quick-start.sh</span>
      </div>

      <div
        className="terminal-screen bg-[#0d1117] p-5 font-mono text-[13px] leading-relaxed"
        aria-label="Quick start commands"
      >
        {completedLines.map((line, index) => (
          <CommandLine key={`${line}-${index}`} text={line} />
        ))}

        {!finished && !isPaused && (
          <CommandLine text={currentLine} active showCursor />
        )}

        {finished && <CommandLine text="" showCursor />}
      </div>
    </div>
  );
}
