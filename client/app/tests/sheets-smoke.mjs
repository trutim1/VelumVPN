// Browser-only UI regression with synthetic IPC summaries. Run against Vite;
// this test never reads a native profile, provisions a peer, or starts a tunnel.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const baseURL = process.env.VELUM_UI_TEST_URL || 'http://127.0.0.1:5173';
const baseOrigin = new URL(baseURL).origin;
const output = new URL('../../docs/local/ui-sheets-20260928/', import.meta.url);
const translationFailures = [];
// Vite has no response CSP. Mirror the real desktop policy for this UI test;
// local antivirus browser injection is not application-owned traffic.
const desktopConfig = JSON.parse(await readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
await mkdir(output, { recursive: true });

const profiles = [
  { name: 'Германия Test', protocol: 'amnezia_wg_legacy', summary: { fingerprint: 'synthetic-fingerprint-one', addresses: ['10.8.1.2/32'], endpoints: ['203.0.113.10:42015'], awg_parameters: ['Jc', 'S1', 'S2', 'S3', 'S4'] } },
  { name: 'Desktop-copy', protocol: 'amnezia_wg_legacy', summary: { fingerprint: 'synthetic-fingerprint-two', addresses: ['10.8.1.3/32'], endpoints: ['203.0.113.10:42015'], awg_parameters: ['Jc', 'S1', 'S2', 'S3', 'S4'] } },
  { name: 'London-V3', protocol: 'amnezia_wg3', summary: { fingerprint: 'synthetic-fingerprint-three', addresses: ['10.77.0.3/32'], endpoints: ['203.0.113.10:42016'], awg_parameters: ['HeaderProtectionKey', 'S1', 'S2', 'S3', 'S4'] } },
];
const protocols = [
  { id: 'amnezia_wg_legacy', name: 'AmneziaWG 1/2', summary: 'Совместимость с существующими профилями AmneziaWG', target_release_track: 'general_availability', implementation: 'import_and_storage', target_platforms: ['windows', 'linux', 'android', 'ios', 'macos'], config_formats: ['conf', 'vpn'], docker_server: true },
  { id: 'amnezia_wg3', name: 'AmneziaWG 3.0', summary: 'WireGuard-криптография с DPI-обфускацией AWG 3', target_release_track: 'preview', implementation: 'import_and_storage', target_platforms: ['windows', 'linux', 'android', 'ios', 'macos'], config_formats: ['conf'], docker_server: true },
];

const browser = await chromium.launch({
  headless: true,
  channel: process.env.VELUM_TEST_BROWSER_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined),
});

async function newScenario(selectedProfiles) {
  const context = await browser.newContext({ viewport: { width: 380, height: 720 }, locale: 'ru-RU' });
  const page = await context.newPage();
  page.setDefaultTimeout(8_000);
  const errors = [];
  const externalRequests = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin === baseOrigin) {
      if (route.request().isNavigationRequest()) {
        const response = await route.fetch();
        return route.fulfill({ response, headers: { ...response.headers(), 'content-security-policy': desktopConfig.app.security.csp } });
      }
      return route.continue();
    }
    externalRequests.push(url.origin);
    return route.abort('blockedbyclient');
  });
  await page.addInitScript(({ selectedProfiles, protocols }) => {
    window.__VELUM_TEST_CALLS__ = [];
    window.__VELUM_TEST_FORBIDDEN__ = [];
    window.__TAURI_INTERNALS__ = {
      invoke: async command => {
        window.__VELUM_TEST_CALLS__.push(command);
        if (command === 'list_profiles') return structuredClone(selectedProfiles);
        if (command === 'list_protocols') return structuredClone(protocols);
        if (command === 'load_application_rules') return { schema_version: 1, mode: 'off', applications: [] };
        if (command === 'tunnel_status') return { state: 'disconnected', profile: null, message: null, platform: 'windows', backend_trusted: false };
        window.__VELUM_TEST_FORBIDDEN__.push(command);
        throw new Error(`UI test forbids non-read IPC: ${command}`);
      },
    };
  }, { selectedProfiles, protocols });
  await page.goto(baseURL);
  await page.waitForFunction(name => document.querySelector('#profile-name')?.textContent === name, selectedProfiles[0].name);
  return { context, page, errors, externalRequests };
}

async function dialogReady(page, title) {
  const dialog = page.locator('#bottom-sheet');
  await dialog.waitFor({ state: 'visible' });
  if (title) await page.locator('#sheet-title').filter({ hasText: title }).waitFor();
  await dialog.evaluate(element => Promise.all(element.getAnimations().map(animation => animation.finished.catch(() => {}))));
  assert.equal(await dialog.evaluate(element => element.matches(':modal')), true, 'sheet must use the native modal top layer');
  const layout = await dialog.evaluate(element => {
    const rect = element.getBoundingClientRect();
    const content = element.querySelector('#sheet-content');
    return { x: rect.left, y: rect.top, right: rect.right, bottom: rect.bottom, width: innerWidth, height: innerHeight, overflow: content.scrollWidth > content.clientWidth + 1 };
  });
  assert.ok(layout.x >= -1 && layout.y >= -1 && layout.right <= layout.width + 1 && layout.bottom <= layout.height + 1, 'sheet must fit the viewport');
  assert.equal(layout.overflow, false, 'sheet content must not overflow horizontally');
}

async function dismiss(page) {
  await page.keyboard.press('Escape');
  await page.locator('#bottom-sheet').waitFor({ state: 'hidden' });
}

async function navigate(page, screen) {
  const selector = `.bottom-nav:visible [data-action="${screen}"], .bottom-nav:visible [data-screen="${screen}"]`;
  await page.locator(selector).click();
  if (screen === 'home') await page.locator('.home-view').waitFor({ state: 'visible' });
  else await page.waitForFunction(value => document.querySelector('#screen-content')?.dataset.screen === value, screen);
}

async function assertNoRussianAuthoredCopy(page, label) {
  const visibleStrings = await page.evaluate(() => {
    const visible = element => {
      if (!element.getClientRects().length) return false;
      for (let node = element; node; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0) return false;
      }
      return true;
    };
    const strings = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const text = walker.currentNode;
      if (text.parentElement && visible(text.parentElement)) strings.push(text.textContent.trim());
    }
    for (const element of document.querySelectorAll('[title], [aria-label], [placeholder]')) {
      if (!visible(element)) continue;
      for (const attribute of ['title', 'aria-label', 'placeholder']) strings.push(element.getAttribute(attribute) || '');
    }
    return strings.filter(Boolean);
  });
  const remaining = visibleStrings.map(value => profiles.reduce((text, profile) => text.replaceAll(profile.name, ''), value))
    .filter(value => /[А-Яа-яЁё]/u.test(value));
  if (remaining.length) translationFailures.push({ label, remaining });
}

async function assertReadOnlyAndPrivate(scenario, expectedLanguage) {
  const { page, errors, externalRequests } = scenario;
  const state = await page.evaluate(() => ({
    forbidden: window.__VELUM_TEST_FORBIDDEN__,
    calls: window.__VELUM_TEST_CALLS__,
    storage: Object.fromEntries(Object.entries(localStorage)),
    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
  }));
  assert.deepEqual(state.forbidden, [], 'no import, connect, disconnect or provisioning IPC');
  assert.ok(state.calls.every(command => ['list_profiles', 'tunnel_status', 'list_protocols', 'load_application_rules'].includes(command)), 'IPC allowlist');
  assert.deepEqual(state.storage, expectedLanguage ? { 'velum.language': expectedLanguage } : {}, 'only the language preference may be persisted');
  assert.deepEqual(state.sessionStorage, {}, 'no profile data in session storage');
  const serialized = JSON.stringify(state.storage);
  for (const profile of profiles) {
    assert.ok(!serialized.includes(profile.name) && !serialized.includes(profile.summary.fingerprint) && !serialized.includes(profile.summary.endpoints[0]), 'profile values must not be persisted in web storage');
  }
  assert.deepEqual(errors, [], 'no uncaught browser errors');
  assert.deepEqual(externalRequests, [], 'UI must not request external endpoints');
}

async function testSplitModal(page) {
  await page.locator('#split-shortcut').click();
  await dialogReady(page, 'Раздельное VPN-туннелирование');
  assert.equal(await page.locator('#sheet-content [data-split="sites"]').count(), 1);
  assert.equal(await page.locator('#sheet-content [data-split="apps"]').count(), 1);
  for (let index = 0; index < 7; index++) {
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => {
      // Native Chromium dialogs may cycle into browser chrome (body becomes
      // activeElement). No application control behind the modal may be focused.
      return document.activeElement === document.body
        || document.querySelector('#bottom-sheet').contains(document.activeElement);
    }), true, 'Tab must not focus application controls behind the native modal');
  }
  await page.locator('.sheet-close').focus();
  assert.equal(await page.evaluate(() => {
    document.querySelector('.home-view [data-action="settings"]').focus();
    return document.querySelector('#bottom-sheet').contains(document.activeElement);
  }), true, 'underlying nav must remain inert');
  await page.locator('[data-split="sites"]').click();
  await dialogReady(page, 'Сайты и сети');
  await page.locator('#sheet-content [data-policy="only_selected"]').click();
  await page.locator('#sheet-content #networks').fill('10.99.0.0/16, 192.0.2.0/24');
  await page.locator('.sheet-back').click();
  await dialogReady(page, 'Раздельное VPN-туннелирование');
  await page.locator('[data-split="sites"]').click();
  assert.equal(await page.locator('#sheet-content #networks').inputValue(), '10.99.0.0/16, 192.0.2.0/24', 'moving route panel must preserve its draft');
  await dismiss(page);
  assert.equal(await page.locator('#split-shortcut').evaluate(element => document.activeElement === element), true, 'Escape must restore the original opener');
  assert.equal(await page.locator('#route-panel').isVisible(), false, 'route panel must be restored to hidden storage');
  await page.locator('#split-shortcut').click();
  await dialogReady(page);
  await page.locator('[data-split="sites"]').click();
  assert.equal(await page.locator('#sheet-content #networks').inputValue(), '10.99.0.0/16, 192.0.2.0/24', 'draft survives a close and reopen');
  await page.locator('.sheet-back').click();
  await page.locator('[data-split="apps"]').click();
  await dialogReady(page, 'Туннелирование приложений');
  assert.equal(await page.locator('input[name="app-mode"]').count(), 3, 'off/include/exclude draft modes');
  assert.match(await page.locator('.app-rules-warning').innerText(), /не работающая маршрутизация/, 'draft must not pretend to edit OS policy');
  assert.equal(await page.locator('#save-applications').isEnabled(), true);
  await page.screenshot({ path: fileURLToPath(new URL('application-rules.png', output)) });
  await page.locator('.sheet-back').click();
  await dialogReady(page);
  await page.screenshot({ path: fileURLToPath(new URL('split-menu.png', output)) });
  const bounds = await page.locator('#bottom-sheet').boundingBox();
  assert.ok(bounds && bounds.y > 5, 'sheet leaves room for backdrop regression');
  await page.mouse.move(bounds.x + 70, bounds.y + 30);
  await page.mouse.down();
  await page.mouse.move(5, 5);
  await page.mouse.up();
  assert.equal(await page.locator('#bottom-sheet').isVisible(), true, 'drag starting inside must not dismiss the sheet');
  await page.mouse.click(5, 5);
  await page.locator('#bottom-sheet').waitFor({ state: 'hidden' });
}

async function testServerGrouping(page, expectedServers) {
  await page.locator('#profile-select').click();
  await dialogReady(page, 'Сервер и подключение');
  assert.equal(await page.locator('#available-servers [role="radio"]').count(), expectedServers, 'same endpoint must group, different port must remain separate');
  assert.equal(await page.locator('#available-servers strong').first().textContent(), profiles[0].name, 'server name remains user data');
  await page.locator('#server-protocol-picker').click();
  await dialogReady(page, 'Протокол');
  const names = await page.locator('#sheet-content .sheet-option-main small').allTextContents();
  assert.deepEqual(names, profiles.slice(0, 2).map(profile => profile.name), 'connection picker contains only profiles of the selected endpoint');
  assert.ok(!(await page.locator('#sheet-content').innerText()).includes('3.0'), 'other server AWG3 must not enter a legacy server picker');
  await page.locator('.sheet-back').click();
  await dialogReady(page, 'Сервер и подключение');
  if (expectedServers > 1) {
    await page.locator('#available-servers [role="radio"]').nth(1).click();
    await page.locator('#server-protocol-picker').click();
    await dialogReady(page, 'Протокол');
    assert.deepEqual(await page.locator('#sheet-content .sheet-option-main small').allTextContents(), [profiles[2].name]);
    await page.locator('.sheet-back').click();
    await page.locator('#available-servers [role="radio"]').first().click();
  }
  await dismiss(page);
}

async function testShareForm(page, singleServer) {
  await navigate(page, 'share');
  await page.locator('#peer-name').waitFor();
  assert.equal(await page.locator('#peer-name').isEnabled(), true, 'user can prepare a local peer name');
  await page.locator('#peer-name').fill('Synthetic E2E user');
  assert.equal(await page.locator('#peer-server').isDisabled(), singleServer, 'sole server must be selected without a fake selector');
  assert.equal(await page.locator('#create-peer').isDisabled(), true, 'valid imported-only draft cannot create a server user');
  assert.ok(!(await page.locator('#peer-protocol').innerText()).includes('3.0'));
  if (await page.locator('#peer-protocol').isEnabled()) {
    await page.locator('#peer-protocol').click();
    await dialogReady(page, 'Протокол');
    const choices = await page.locator('#sheet-content [role="radio"]').allTextContents();
    assert.equal(choices.length, 1, 'legacy target must offer only its observed protocol');
    assert.ok(!choices.some(value => value.includes('3.0')));
    await dismiss(page);
  }
  assert.equal(await page.locator('#peer-name').inputValue(), 'Synthetic E2E user');
  if (!singleServer) {
    await page.locator('#peer-server').click();
    await dialogReady(page, 'Сервер');
    await page.locator('#sheet-content [role="radio"]').nth(1).click();
    assert.ok((await page.locator('#peer-protocol').innerText()).includes('3.0'), 'choosing the AWG3 target must update the draft protocol');
    assert.equal(await page.locator('#create-peer').isDisabled(), true);
    assert.equal(await page.locator('#peer-name').inputValue(), 'Synthetic E2E user', 'server changes preserve the entered user name');
  }
  await page.screenshot({ path: fileURLToPath(new URL(singleServer ? 'share-single-server.png' : 'share-multiple-servers.png', output)) });
}

async function testLanguage(scenario) {
  const { page } = scenario;
  await navigate(page, 'settings');
  await page.locator('[data-screen="application"]').click();
  await page.locator('[data-action="language"]').click();
  await dialogReady(page, 'Язык приложения');
  await page.getByRole('radio', { name: 'English', exact: true }).click();
  await page.waitForFunction(() => document.documentElement.lang === 'en');
  await page.locator('#bottom-sheet').waitFor({ state: 'hidden' });
  await assertNoRussianAuthoredCopy(page, 'English application settings');
  await navigate(page, 'home');
  assert.equal(await page.locator('#profile-name').textContent(), profiles[0].name, 'language must not translate a user-provided server label');
  await assertNoRussianAuthoredCopy(page, 'English home');
  await page.locator('#profile-select').click();
  await dialogReady(page);
  assert.equal(await page.locator('#available-servers strong').first().textContent(), profiles[0].name);
  await assertNoRussianAuthoredCopy(page, 'English server sheet');
  await dismiss(page);
  await page.locator('#split-shortcut').click();
  await dialogReady(page);
  await assertNoRussianAuthoredCopy(page, 'English split menu');
  await page.locator('[data-split="sites"]').click();
  await dialogReady(page);
  await assertNoRussianAuthoredCopy(page, 'English network rules');
  await dismiss(page);
  for (const screen of ['share', 'settings', 'add']) {
    await navigate(page, screen);
    await assertNoRussianAuthoredCopy(page, `English ${screen}`);
  }
  await navigate(page, 'settings');
  for (const screen of ['application', 'security', 'backup', 'protocols']) {
    await page.locator(`.settings-list [data-screen="${screen}"]`).click();
    if (screen === 'protocols') await page.locator('.protocol-card').first().waitFor();
    await assertNoRussianAuthoredCopy(page, `English ${screen}`);
    await page.locator('#screen-back').click();
  }
  await page.reload();
  await page.waitForFunction(name => document.querySelector('#profile-name')?.textContent === name, profiles[0].name);
  assert.equal(await page.locator('html').getAttribute('lang'), 'en', 'language preference survives reload');
  await assertNoRussianAuthoredCopy(page, 'English after reload');
  await assertReadOnlyAndPrivate(scenario, 'en');
  await page.screenshot({ path: fileURLToPath(new URL('english-home.png', output)) });
  assert.deepEqual(translationFailures, [], 'authored RU copy remains after switching to English');
}

try {
  const single = await newScenario(profiles.slice(0, 2));
  try {
    await testSplitModal(single.page);
    await testServerGrouping(single.page, 1);
    await testShareForm(single.page, true);
    await testLanguage(single);
    console.log('SHEETS_SINGLE_SERVER_OK: split/back/Escape/draft, modal focus/backdrop, grouped profiles, imported-only peer form, RU/EN persistence.');
  } finally {
    await single.context.close();
  }
  const multiple = await newScenario(profiles);
  try {
    await testServerGrouping(multiple.page, 2);
    await testShareForm(multiple.page, false);
    await assertReadOnlyAndPrivate(multiple);
    console.log('SHEETS_MULTIPLE_SERVERS_OK: port-separated targets, protocol isolation, name preservation, no provisioning authority.');
  } finally {
    await multiple.context.close();
  }
} finally {
  await browser.close();
}
