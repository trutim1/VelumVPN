// Browser-only application-rule regression. IPC and executable metadata are
// synthetic. No native picker, file import, service or VPN command is executed.
// The in-memory encrypted mock is NOT Windows DPAPI and does not test dataplane
// enforcement, native permissions or the absence of Windows traffic leaks.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const baseURL = process.env.VELUM_UI_TEST_URL || 'http://127.0.0.1:5173';
const baseOrigin = new URL(baseURL).origin;
const desktopConfig = JSON.parse(await readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
const environmentalOrigins = new Set([
  'http://me.kis.v2.scr.kaspersky-labs.com',
  'https://me.kis.v2.scr.kaspersky-labs.com',
  'http://gc.kis.v2.scr.kaspersky-labs.com',
  'https://gc.kis.v2.scr.kaspersky-labs.com',
]);
const profile = {
  name: 'Synthetic UI profile', protocol: 'amnezia_wg_legacy',
  summary: { fingerprint: 'synthetic-only', addresses: ['10.8.1.2/32'], endpoints: ['203.0.113.10:42015'], awg_parameters: ['Jc', 'S1', 'S2'] },
};
const browserApp = { id: '1'.repeat(64), name: 'browser.exe', path: 'C:\\Приложения\\Мой Браузер\\browser.exe' };
const chatApp = { id: '2'.repeat(64), name: 'chat.exe', path: 'C:\\Tools\\Чат & встречи\\chat.exe' };
const rules = (mode = 'off', applications = [browserApp]) => ({ schema_version: 1, mode, applications: structuredClone(applications) });
const allowedCommands = new Set(['list_profiles', 'list_protocols', 'tunnel_status', 'load_application_rules', 'select_application', 'save_application_rules']);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

// Model only the native-storage boundary: ciphertext lives in the test runner,
// never localStorage/sessionStorage. Nothing is written to the user's files.
function encryptedMemory(initial) {
  const key = randomBytes(32);
  let ciphertext, nonce, tag;
  const write = value => {
    nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    tag = cipher.getAuthTag();
  };
  const read = () => {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
  };
  write(initial);
  return { write, read, opaque: () => !ciphertext.includes(Buffer.from(browserApp.path)) };
}

const browser = await chromium.launch({
  headless: true,
  channel: process.env.VELUM_TEST_BROWSER_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined),
});

async function newScenario({ initial = rules(), delayLoad = false, rejectLoad = false } = {}) {
  const context = await browser.newContext({ viewport: { width: 380, height: 720 }, locale: 'ru-RU' });
  const page = await context.newPage();
  page.setDefaultTimeout(8_000);
  const storage = encryptedMemory(initial);
  const native = { calls: [], forbidden: [], saved: [], selections: [], loadGate: delayLoad ? deferred() : null, saveGate: null, rejectLoad, storage };
  const errors = [];
  const blockedRequests = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== baseOrigin) {
      blockedRequests.push({ origin: url.origin, environmental: environmentalOrigins.has(url.origin) });
      return route.abort('blockedbyclient');
    }
    if (route.request().isNavigationRequest()) {
      const response = await route.fetch();
      return route.fulfill({ response, headers: { ...response.headers(), 'content-security-policy': desktopConfig.app.security.csp } });
    }
    return route.continue();
  });
  await page.exposeFunction('__VELUM_SYNTHETIC_NATIVE__', async (command, args) => {
    native.calls.push(command);
    if (!allowedCommands.has(command)) {
      native.forbidden.push(command);
      throw new Error(`Forbidden real-operation boundary: ${command}`);
    }
    if (command === 'list_profiles') return [structuredClone(profile)];
    if (command === 'list_protocols') return [];
    if (command === 'tunnel_status') return { state: 'disconnected', profile: null, message: null, platform: 'windows', backend_trusted: true };
    if (command === 'load_application_rules') {
      if (native.loadGate) await native.loadGate.promise;
      if (native.rejectLoad) throw new Error('Synthetic encrypted-store read failure');
      return storage.read();
    }
    if (command === 'select_application') return structuredClone(native.selections.shift() ?? null);
    if (command === 'save_application_rules') {
      const value = structuredClone(args.rules);
      assert.equal(value.schema_version, 1);
      assert.ok(['off', 'include', 'exclude'].includes(value.mode));
      assert.ok(value.applications.every(app => [browserApp, chatApp].some(known => JSON.stringify(known) === JSON.stringify(app))), 'only fixture applications may cross the mock save boundary');
      if (native.saveGate) await native.saveGate.promise;
      storage.write(value);
      native.saved.push(value);
      return storage.read();
    }
    throw new Error('Unhandled mock command');
  });
  await page.addInitScript(() => {
    window.__VELUM_PENDING__ = {};
    window.__VELUM_CSP_VIOLATIONS__ = [];
    window.addEventListener('securitypolicyviolation', event => {
      window.__VELUM_CSP_VIOLATIONS__.push({ blocked: event.blockedURI, directive: event.effectiveDirective });
    });
    window.__TAURI_INTERNALS__ = {
      invoke: async (command, args) => {
        window.__VELUM_PENDING__[command] = (window.__VELUM_PENDING__[command] || 0) + 1;
        try { return await window.__VELUM_SYNTHETIC_NATIVE__(command, args); }
        finally { window.__VELUM_PENDING__[command]--; }
      },
    };
  });
  await page.goto(baseURL);
  await page.waitForFunction(name => document.querySelector('#profile-name')?.textContent === name, profile.name);
  if (!delayLoad) await idle(page, 'load_application_rules');
  return { context, page, native, errors, blockedRequests };
}

async function idle(page, command) {
  await page.waitForFunction(value => window.__VELUM_PENDING__[value] === 0, command);
}

async function dialogReady(page) {
  await page.locator('#bottom-sheet').waitFor({ state: 'visible' });
  assert.equal(await page.locator('#bottom-sheet').evaluate(element => element.matches(':modal')), true);
  await page.locator('#bottom-sheet').evaluate(element => Promise.all(element.getAnimations().map(animation => animation.finished.catch(() => {}))));
}

async function openApplications(page) {
  if (!await page.locator('#bottom-sheet').isVisible()) {
    await page.locator('#split-shortcut').click();
    await dialogReady(page);
  }
  await page.locator('[data-split="apps"]').click();
  await page.locator('#save-applications').waitFor();
}

async function dismiss(page) {
  await page.keyboard.press('Escape');
  await page.locator('#bottom-sheet').waitFor({ state: 'hidden' });
}

async function save(page) {
  await page.locator('#save-applications').click();
  await idle(page, 'save_application_rules');
  await page.waitForFunction(() => !document.querySelector('#save-applications')?.disabled);
}

async function assertBoundary(scenario, language) {
  const { page, native, errors, blockedRequests } = scenario;
  assert.deepEqual(native.forbidden, [], 'no connect/disconnect/import/provisioning or unlisted native IPC');
  assert.ok(native.calls.every(command => allowedCommands.has(command)));
  const state = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, csp: window.__VELUM_CSP_VIOLATIONS__ }));
  assert.deepEqual(state.local, language ? { 'velum.language': language } : {}, 'application paths and rule modes never enter browser persistence');
  assert.deepEqual(state.session, {});
  assert.equal(native.storage.opaque(), true);
  assert.deepEqual(errors, [], 'no uncaught browser errors');
  assert.deepEqual(blockedRequests.filter(request => !request.environmental), [], 'unexpected external requests must fail the test');
  const sourceLabel = value => {
    try { return new URL(value).origin; } catch { return value; }
  };
  console.log('APP_RULES_ENVIRONMENT', JSON.stringify({
    blockedAntivirusRequests: blockedRequests.filter(request => request.environmental),
    cspBlockedSources: [...new Set(state.csp.map(violation => sourceLabel(violation.blocked)))],
    scope: 'Synthetic browser UI under desktop CSP; not native network-leak evidence.',
  }));
}

async function testEditorAndLanguage() {
  const scenario = await newScenario();
  const { page, native } = scenario;
  try {
    assert.equal(await page.locator('#power').isEnabled(), true, 'Off permits the trusted mock button; do not invoke connect');
    await openApplications(page);
    assert.equal(await page.locator('#app-rules-list small').textContent(), browserApp.path);
    assert.match(await page.locator('.app-rules-warning').innerText(), /не работающая маршрутизация/);
    native.selections.push(chatApp, chatApp, null, chatApp);
    for (let index = 0; index < 3; index++) {
      await page.locator('#add-application').click();
      await idle(page, 'select_application');
    }
    assert.equal(await page.locator('.application-rule').count(), 2, 'duplicate selection and cancellation do not duplicate entries');
    assert.deepEqual(native.storage.read(), rules(), 'edits are drafts until saved');
    await page.locator('#app-search').fill('ЧАТ & встречи');
    assert.equal(await page.locator('.application-rule').count(), 1);
    assert.equal(await page.locator('.application-rule small').textContent(), chatApp.path, 'special characters remain literal data');
    await page.locator('.application-rule button').click();
    await page.locator('#app-search').fill('');
    assert.equal(await page.locator('.application-rule').count(), 1, 'remove affects only the matched draft application');
    await page.locator('#add-application').click();
    await idle(page, 'select_application');
    await page.locator('input[name="app-mode"][value="include"]').check();
    await save(page);
    assert.deepEqual(native.storage.read(), rules('include', [browserApp, chatApp]));
    await dismiss(page);
    assert.equal(await page.locator('#power').isDisabled(), true, 'saved Include must block connect');
    await page.locator('#power').dispatchEvent('click');
    assert.deepEqual(native.forbidden, [], 'click-handler guard also rejects synthetic dispatch while Include is set');
    await openApplications(page);
    assert.equal(await page.locator('input[value="include"]').isChecked(), true);
    assert.deepEqual(await page.locator('.application-rule small').allTextContents(), [browserApp.path, chatApp.path]);
    await page.locator('input[value="off"]').check();
    await save(page);
    await dismiss(page);
    assert.equal(await page.locator('#power').isEnabled(), true, 'Off restores only button eligibility, without invoking any VPN command');
    assert.deepEqual(native.storage.read(), rules('off', [browserApp, chatApp]), 'Off preserves selected metadata');

    await page.locator('.bottom-nav:visible [data-action="settings"]').click();
    await page.locator('[data-screen="application"]').click();
    await page.locator('[data-action="language"]').click();
    await page.getByRole('radio', { name: 'English', exact: true }).click();
    await page.waitForFunction(() => document.documentElement.lang === 'en');
    await page.locator('.bottom-nav:visible [data-screen="home"]').click();
    await openApplications(page);
    assert.match(await page.locator('.app-rules-warning').innerText(), /not working per-app routing/);
    assert.deepEqual(await page.locator('.application-rule small').allTextContents(), [browserApp.path, chatApp.path], 'English UI must preserve literal Cyrillic paths');
    const authored = await page.locator('#sheet-content').evaluate(element => {
      const copy = element.cloneNode(true);
      copy.querySelectorAll('[data-dynamic]').forEach(node => node.remove());
      return copy.textContent;
    });
    assert.doesNotMatch(authored, /[А-Яа-яЁё]/u, 'application-editor authored strings are translated');
    await assertBoundary(scenario, 'en');
    console.log('APP_RULES_EDITOR_OK: load/add/cancel/deduplicate/remove/search/save, Include gate, Off recovery, literal RU/EN paths.');
  } finally { await scenario.context.close(); }
}

async function testDelayedLoad() {
  const scenario = await newScenario({ initial: rules('include'), delayLoad: true });
  const { page, native } = scenario;
  try {
    assert.equal(await page.locator('#power').isDisabled(), true);
    await page.locator('#split-shortcut').click();
    await dialogReady(page);
    await page.locator('[data-split="apps"]').click();
    assert.equal(await page.locator('#save-applications').count(), 0, 'do not create an empty editable draft before loading');
    assert.equal(native.saved.length, 0);
    native.loadGate.resolve();
    await idle(page, 'load_application_rules');
    await openApplications(page);
    await page.locator('#app-search').fill('browser');
    assert.equal(await page.locator('input[value="include"]').isChecked(), true);
    assert.equal(await page.locator('.application-rule small').textContent(), browserApp.path);
    assert.deepEqual(native.storage.read(), rules('include'));
    assert.equal(native.saved.length, 0, 'late load/search must never overwrite saved rules');
    await assertBoundary(scenario);
    console.log('APP_RULES_DELAYED_LOAD_OK: fail-closed until loaded, no stale empty draft overwrite.');
  } finally { native.loadGate.resolve(); await scenario.context.close(); }
}

async function testPendingSave() {
  const scenario = await newScenario();
  const { page, native } = scenario;
  try {
    await openApplications(page);
    await page.locator('input[value="exclude"]').check();
    native.saveGate = deferred();
    await page.locator('#save-applications').click();
    await page.waitForFunction(() => window.__VELUM_PENDING__.save_application_rules === 1);
    await dismiss(page);
    await page.locator('#split-shortcut').click();
    await dialogReady(page);
    await page.locator('[data-split="apps"]').click();
    assert.equal(await page.locator('#save-applications').count(), 0, 'reopening cannot create a second editor while save is pending');
    await page.locator('[data-split="sites"]').click();
    await page.locator('#sheet-content [data-policy="only_selected"]').click();
    await page.locator('#networks').fill('198.51.100.0/24');
    const networkTitle = await page.locator('#sheet-title').textContent();
    native.saveGate.resolve();
    await idle(page, 'save_application_rules');
    assert.equal(await page.locator('#sheet-title').textContent(), networkTitle, 'late save must not replace the newer sheet');
    assert.equal(await page.locator('#networks').inputValue(), '198.51.100.0/24');
    assert.equal(await page.locator('#save-applications').count(), 0);
    assert.deepEqual(native.storage.read(), rules('exclude'));
    await dismiss(page);
    await openApplications(page);
    assert.equal(await page.locator('input[value="exclude"]').isChecked(), true, 'reopened draft uses committed data');
    assert.equal(await page.locator('.application-rule small').textContent(), browserApp.path);
    await assertBoundary(scenario);
    console.log('APP_RULES_PENDING_SAVE_OK: busy reopen gate, late callback isolation, committed draft restored.');
  } finally { native.saveGate?.resolve(); await scenario.context.close(); }
}

async function testLoadError() {
  const scenario = await newScenario({ rejectLoad: true });
  const { page, native } = scenario;
  try {
    assert.equal(await page.locator('#power').isDisabled(), true, 'failed encrypted storage read blocks connect');
    await page.locator('#power').dispatchEvent('click');
    await openApplications(page);
    assert.equal(await page.locator('#add-application').isDisabled(), true);
    assert.equal(await page.locator('#save-applications').isDisabled(), true);
    for (const mode of ['off', 'include', 'exclude']) assert.equal(await page.locator(`input[value="${mode}"]`).isDisabled(), true);
    assert.match(await page.locator('#app-rules-note').innerText(), /Не удалось прочитать/);
    assert.equal(native.saved.length, 0, 'read failure must not silently reset existing rules');
    await page.locator('#reset-applications').click();
    assert.equal(native.saved.length, 0, 'reset requires explicit second confirmation');
    await page.locator('#cancel-reset-applications').click();
    assert.equal(await page.locator('#confirm-app-reset').isVisible(), false);
    assert.equal(native.saved.length, 0);
    // Even a successful native save must not unlock connection if reload fails.
    await page.locator('#reset-applications').click();
    await page.locator('#confirm-reset-applications').click();
    await idle(page, 'save_application_rules');
    await idle(page, 'load_application_rules');
    assert.equal(await page.locator('#power').isDisabled(), true);
    assert.equal(await page.locator('#save-applications').isDisabled(), true);
    assert.deepEqual(native.saved[0], rules('off', []));
    native.rejectLoad = false;
    await page.locator('#confirm-reset-applications').click();
    await idle(page, 'save_application_rules');
    await idle(page, 'load_application_rules');
    await page.waitForFunction(() => document.querySelector('#app-rules-recovery')?.hidden === true);
    assert.equal(await page.locator('input[value="off"]').isChecked(), true);
    assert.equal(await page.locator('#save-applications').isDisabled(), false);
    assert.deepEqual(native.storage.read(), rules('off', []));
    await assertBoundary(scenario);
    console.log('APP_RULES_LOAD_ERROR_OK: failure stays closed; explicit reset confirmation/cancel and native reload recovery.');
  } finally { await scenario.context.close(); }
}

try {
  await testEditorAndLanguage();
  await testDelayedLoad();
  await testPendingSave();
  await testLoadError();
} finally { await browser.close(); }
