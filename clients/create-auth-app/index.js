#!/usr/bin/env node
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import {
  planScaffold,
  writeScaffold,
  isDirUsable,
  HOSTED_SERVER_URL,
} from './src/scaffold.js';
import { templateNames } from './src/templates.js';

const HELP = `create-auth-app — scaffold an app wired up with @authserver/client

Usage:
  npm create auth-app@latest [dir] -- [options]
  npx create-auth-app [dir] [options]

Options:
  -t, --template <name>    One of: ${templateNames.join(', ')}
  -s, --server <url>       Auth server URL (default: hosted demo server)
      --client-id <id>     Your OAuth client ID
  -y, --yes                Skip prompts; use defaults for anything not provided
  -h, --help               Show this help

Examples:
  npm create auth-app@latest my-app -- --template next
  npx create-auth-app my-app -t react --client-id abc123
`;

/** Minimal flag parser supporting "--flag value", "--flag=value", and short aliases. */
function parseArgs(argv) {
  const out = { _: [] };
  const alias = { t: 'template', s: 'server', y: 'yes', h: 'help' };
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    if (!arg.startsWith('-')) {
      out._.push(arg);
      continue;
    }
    arg = arg.replace(/^-+/, '');
    let value;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      value = arg.slice(eq + 1);
      arg = arg.slice(0, eq);
    }
    const key = alias[arg] || arg;
    if (key === 'yes' || key === 'help') {
      out[key] = true;
      continue;
    }
    if (value === undefined) {
      value = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : '';
    }
    out[key] = value;
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    stdout.write(HELP);
    return;
  }

  const interactive = stdin.isTTY && !args.yes;
  const rl = interactive ? createInterface({ input: stdin, output: stdout }) : null;
  const ask = async (question, fallback) => {
    if (!rl) return fallback;
    const answer = (await rl.question(question)).trim();
    return answer || fallback;
  };

  try {
    let dir = args._[0] || (await ask('Project directory: (my-auth-app) ', 'my-auth-app'));

    let template = args.template;
    if (!templateNames.includes(template)) {
      template = await ask(`Template — ${templateNames.join(' / ')}: (next) `, 'next');
    }

    const serverUrl =
      args.server || (await ask(`Auth server URL: (${HOSTED_SERVER_URL}) `, HOSTED_SERVER_URL));
    const clientId =
      args['client-id'] || (await ask('OAuth client ID: (set later) ', ''));

    const plan = planScaffold({ dir, template, serverUrl, clientId });

    if (!(await isDirUsable(plan.dir))) {
      throw new Error(`Target directory "${plan.dir}" already exists and is not empty.`);
    }

    const root = await writeScaffold(plan);

    rl?.close();
    printSuccess(plan, root);
  } catch (error) {
    rl?.close();
    stdout.write(`\n✖ ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}

function printSuccess(plan, root) {
  stdout.write(`\n✔ Created ${plan.template} app in ${root}\n\n`);
  stdout.write(`Server:  ${plan.serverUrl}\n`);
  if (plan.usesPlaceholderClientId) {
    stdout.write(
      `Client:  not set — get one with the "Get a Client ID" guide:\n` +
        `         https://www.npmjs.com/package/@authserver/client#get-a-client-id\n`,
    );
  } else {
    stdout.write(`Client:  ${plan.clientId}\n`);
  }
  stdout.write(`\nNext steps:\n`);
  stdout.write(`  cd ${plan.dir}\n`);
  for (const step of plan.steps) stdout.write(`  ${step}\n`);
  stdout.write('\n');
}

await main();
