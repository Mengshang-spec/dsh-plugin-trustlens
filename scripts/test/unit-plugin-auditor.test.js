'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const auditorUrl = pathToFileURL(path.join(__dirname, '..', '..', 'assets', 'plugins', 'dsh-plugin-auditor', 'lib', 'index.js'));

test('resolveActiveSelection prefers the current session selection and labels its source', async () => {
  const { resolveActiveSelection } = await import(auditorUrl);
  assert.deepEqual(resolveActiveSelection({
    session: { provider: 'openai', model: 'gpt-5' },
    configured: { provider: 'deepseek-official', model: 'deepseek-v4-flash' },
  }), { provider: 'openai', model: 'gpt-5', source: 'session' });
});

test('resolveActiveSelection fails closed when no current model is known', async () => {
  const { resolveActiveSelection } = await import(auditorUrl);
  assert.deepEqual(resolveActiveSelection({ session: {}, configured: {} }), {
    provider: '', model: '', source: 'unknown',
  });
});

test('readActiveSelection reads the configured fallback without hard-coding DeepSeek', async (t) => {
  const { readActiveSelection } = await import(auditorUrl);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-auditor-settings-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'settings.yaml'), 'agent-default-model:\n  provider: openai\n  model: gpt-5\nother:\n  model: wrong\n');
  const previous = process.env.DSH_HOME;
  process.env.DSH_HOME = root;
  t.after(() => { if (previous === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = previous; });
  assert.deepEqual(readActiveSelection(), { provider: 'openai', model: 'gpt-5' });
});

test('packagePathAllowed only accepts a real child of the profile node_modules directory', async (t) => {
  const { packagePathAllowed } = await import(auditorUrl);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-auditor-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const nm = path.join(root, 'node_modules');
  const pkg = path.join(nm, '@scope', 'plugin');
  fs.mkdirSync(pkg, { recursive: true });
  assert.equal(packagePathAllowed(pkg, nm), true);
  assert.equal(packagePathAllowed(path.join(root, 'node_modules-evil', 'plugin'), nm), false);
  assert.equal(packagePathAllowed(path.join(nm, '..', 'outside'), nm), false);
});

test('createAuditHandler sends the session model to ctx.llm and never executes the package', async (t) => {
  const { createAuditHandler } = await import(auditorUrl);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-auditor-pkg-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const nm = path.join(root, 'node_modules');
  const pkg = path.join(nm, 'safe-plugin');
  fs.mkdirSync(pkg, { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), '{"name":"safe-plugin","version":"1.0.0"}');
  fs.writeFileSync(path.join(pkg, 'index.js'), 'process.exit(99);');

  let llmRequest;
  const ctx = {
    llm: { stream: async function* (request) {
      llmRequest = request;
      yield { type: 'text-delta', text: '{"verdict":"safe","findings":[],"commentConflicts":[],"recommendedAction":"allow"}' };
    } },
  };
  const handler = createAuditHandler(ctx, { profileNodeModules: nm, sessionResolver: () => ({ provider: 'openai', model: 'gpt-5' }) });
  const body = {
    pluginId: 'safe-plugin', packageName: 'safe-plugin', packagePath: pkg,
    userRequest: '只读审查', sessionId: 'session-1',
  };
  const response = await handler(body);
  assert.equal(response.status, 200);
  assert.deepEqual(response.value.active, { provider: 'openai', model: 'gpt-5', source: 'session' });
  assert.equal(llmRequest.provider, 'openai');
  assert.equal(llmRequest.model, 'gpt-5');
  assert.match(llmRequest.messages[0].content[0].text, /不要运行插件/);
});

test('client action gate does not enable or update when static findings exist', () => {
  const client = fs.readFileSync(path.join(__dirname, '..', '..', 'assets', 'plugins', 'dsh-plugin-auditor', 'lib', 'client.js'), 'utf8');
  assert.match(client, /const canEnable = report && report\.verdict !== "block" && !result\.staticFindings\?\.length/);
  assert.match(client, /const canUpdate = report && report\.verdict !== "block" && !result\.staticFindings\?\.length/);
});
