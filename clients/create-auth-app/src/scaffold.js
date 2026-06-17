import { mkdir, writeFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { templates, templateNames } from './templates.js';

export const HOSTED_SERVER_URL = 'https://auth-server-4nmm.onrender.com';

/** Convert an arbitrary directory name into a valid npm package name. */
export function toPackageName(input) {
  let cleaned = String(input)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-');
    
  while (cleaned.length > 0 && /[-_.]/.test(cleaned[0])) {
    cleaned = cleaned.slice(1);
  }
  while (cleaned.length > 0 && /[-_.]/.test(cleaned.at(-1))) {
    cleaned = cleaned.slice(0, -1);
  }
  
  return cleaned || 'my-auth-app';
}

/**
 * Pure planning step: validates options and returns the file plan without
 * touching the filesystem. Throws on invalid input.
 *
 * @param {{ dir: string, template: string, serverUrl?: string, clientId?: string }} options
 */
export function planScaffold(options) {
  const dir = (options.dir || '').trim();
  if (!dir) throw new Error('A target directory is required.');
  if (dir.includes('..') || path.isAbsolute(dir)) {
    throw new Error('Directory must be a relative path without ".."');
  }

  const template = options.template;
  if (!templateNames.includes(template)) {
    throw new Error(`Unknown template "${template}". Choose one of: ${templateNames.join(', ')}.`);
  }

  const serverUrl = (options.serverUrl || HOSTED_SERVER_URL).replace(/\/$/, '');
  const clientId = options.clientId || 'your_oauth_client_id';
  const packageName = toPackageName(path.basename(dir));

  const result = templates[template]({ packageName, serverUrl, clientId });

  return {
    dir,
    template,
    serverUrl,
    clientId,
    packageName,
    usesPlaceholderClientId: !options.clientId,
    files: result.files,
    steps: result.steps,
    install: result.install,
    dev: result.dev,
  };
}

/** Ensures the target path does not escape the base directory (prevents path traversal). */
export function ensureSafePath(targetDir, baseDir = process.cwd()) {
  const root = path.resolve(baseDir);
  const target = path.resolve(root, targetDir);
  if (!target.startsWith(root + path.sep) && target !== root) {
    throw new Error('Path traversal detected');
  }
  return target;
}

/** Returns true when `dir` does not exist or exists but is empty. */
export async function isDirUsable(dir) {
  const target = ensureSafePath(dir);
  if (!existsSync(target)) return true;
  const entries = await readdir(target);
  return entries.length === 0;
}

/** Writes a plan's files under `baseDir`/`plan.dir`. */
export async function writeScaffold(plan, baseDir = process.cwd()) {
  const root = ensureSafePath(plan.dir, baseDir);
  for (const file of plan.files) {
    const target = ensureSafePath(file.path, root);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, file.contents, 'utf8');
  }
  return root;
}
