import { planScaffold, toPackageName, HOSTED_SERVER_URL } from './src/scaffold.js';
import { templateNames } from './src/templates.js';

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log('  ok  -', name); } else { fail++; console.log(' FAIL -', name); } };
const find = (plan, p) => plan.files.find((f) => f.path === p);

// toPackageName sanitization
ok('toPackageName lowercases + slugifies', toPackageName('My Cool App') === 'my-cool-app');
ok('toPackageName trims junk', toPackageName('--Weird__') === 'weird');
ok('toPackageName falls back', toPackageName('') === 'my-auth-app');

// unknown template throws
let threw = false;
try { planScaffold({ dir: 'x', template: 'svelte' }); } catch { threw = true; }
ok('unknown template throws', threw);

// missing dir throws
threw = false;
try { planScaffold({ dir: '', template: 'node' }); } catch { threw = true; }
ok('missing dir throws', threw);

// default server is hosted, placeholder client id flagged
const def = planScaffold({ dir: 'demo', template: 'node' });
ok('defaults to hosted server', def.serverUrl === HOSTED_SERVER_URL);
ok('flags placeholder client id', def.usesPlaceholderClientId === true);

// node template content + injection
const node = planScaffold({ dir: 'My App', template: 'node', clientId: 'cid123', serverUrl: 'http://localhost:3000/' });
ok('node has package.json + index.mjs + .env', find(node, 'package.json') && find(node, 'index.mjs') && find(node, '.env'));
ok('node injects clientId into .env', find(node, '.env').contents.includes('AUTH_CLIENT_ID=cid123'));
ok('node strips trailing slash from server', find(node, '.env').contents.includes('AUTH_SERVER_URL=http://localhost:3000\n'));
ok('node package.json uses sanitized name', JSON.parse(find(node, 'package.json').contents).name === 'my-app');
ok('node does not flag placeholder when clientId given', node.usesPlaceholderClientId === false);

// react template
const react = planScaffold({ dir: 'web', template: 'react', clientId: 'c' });
ok('react has vite + App.tsx + main.tsx', find(react, 'vite.config.ts') && find(react, 'src/App.tsx') && find(react, 'src/main.tsx'));
ok('react injects VITE_ env', find(react, '.env').contents.includes('VITE_AUTH_CLIENT_ID=c'));
ok('react imports react bindings', find(react, 'src/main.tsx').contents.includes("@authserver/client/react"));

// next template — the adapter wiring
const next = planScaffold({ dir: 'site', template: 'next', clientId: 'c' });
ok('next has route handler + middleware + dashboard', find(next, 'app/api/auth/[...authserver]/route.ts') && find(next, 'middleware.ts') && find(next, 'app/dashboard/page.tsx'));
ok('next lib/auth uses createAuthServer', find(next, 'lib/auth.ts').contents.includes('createAuthServer'));
ok('next route exports GET/POST handlers', find(next, 'app/api/auth/[...authserver]/route.ts').contents.includes('authServer.handlers'));
ok('next dashboard uses getSession', find(next, 'app/dashboard/page.tsx').contents.includes('getSession'));
ok('next .env.local injected', find(next, '.env.local').contents.includes('AUTH_CLIENT_ID=c'));

// every template produces a valid package.json
for (const t of templateNames) {
  const p = planScaffold({ dir: 'p-' + t, template: t });
  let valid = true;
  try { JSON.parse(find(p, 'package.json').contents); } catch { valid = false; }
  ok(`${t} package.json is valid JSON`, valid);
  ok(`${t} depends on @authserver/client`, find(p, 'package.json').contents.includes('@authserver/client'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
