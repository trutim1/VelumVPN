// UI boundary only: synthetic helper evidence. Never starts a real tunnel.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');
const base = process.env.VELUM_UI_TEST_URL || 'http://127.0.0.1:5174';
const desktop = JSON.parse(await readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
const browser = await chromium.launch({ headless: true, channel: process.platform === 'win32' ? 'msedge' : undefined });
const evidence = {
  service_state: 'running', uapi_state: 'available', config_accepted: true,
  handshake_fresh: true, peer_count: '1', rx_bytes: '18446744073709551615', tx_bytes: '20',
  observed_at_unix_seconds: 1790582400, traffic_verified: false,
};
let checks = 0;
try {
  for (const scenario of ['active', 'unavailable', 'failure', 'late', 'no-tunnel', 'untrusted', 'english']) {
    const context = await browser.newContext({ viewport: { width: 380, height: 720 } });
    const page = await context.newPage();
    const errors = [], outbound = [], forbidden = [], calls = [];
    let complete;
    const deferred = new Promise(resolve => { complete = resolve; });
    page.on('pageerror', error => errors.push(String(error)));
    await page.route('**/*', async route => {
      if (new URL(route.request().url()).origin !== new URL(base).origin) {
        outbound.push(route.request().url());
        return route.abort();
      }
      if (route.request().isNavigationRequest()) {
        const response = await route.fetch();
        return route.fulfill({ response, headers: { ...response.headers(), 'content-security-policy': desktop.app.security.csp } });
      }
      return route.continue();
    });
    await page.exposeFunction('__diagnosticMock', async command => {
      calls.push(command);
      if (command === 'list_profiles') return [{ name: 'fixture', protocol: 'wire_guard', summary: { fingerprint: 'test', addresses: ['10.8.0.2/32'], endpoints: ['203.0.113.1:10000'], awg_parameters: [] } }];
      if (command === 'load_application_rules') return { schema_version: 1, mode: 'off', applications: [] };
      if (command === 'tunnel_status') return {
        state: scenario === 'no-tunnel' ? 'disconnected' : 'awaiting_verification',
        profile: scenario === 'no-tunnel' ? null : 'fixture', platform: 'windows', backend_trusted: scenario !== 'untrusted',
      };
      if (command === 'inspect_tunnel') {
        if (scenario === 'late') await deferred;
        if (scenario === 'failure') throw new Error('SECRET fixture must never reach UI');
        if (scenario === 'unavailable') return { ...evidence, uapi_state: 'unavailable', config_accepted: false, handshake_fresh: false, peer_count: '0', rx_bytes: '0', tx_bytes: '0' };
        return evidence;
      }
      forbidden.push(command);
      throw new Error('Forbidden test command');
    });
    await page.addInitScript(english => {
      localStorage.setItem('velum.language', english ? 'en' : 'ru');
      window.__diagnosticPending = 0;
      window.__TAURI_INTERNALS__ = { invoke: async command => {
        if (command === 'inspect_tunnel') window.__diagnosticPending++;
        try { return await window.__diagnosticMock(command); }
        finally { if (command === 'inspect_tunnel') window.__diagnosticPending--; }
      } };
    }, scenario === 'english');
    await page.goto(base);
    await page.waitForFunction(() => document.querySelector('#profile-name')?.textContent === 'fixture');
    await page.locator('.bottom-nav:visible [data-action="settings"]').click();
    await page.locator('[data-screen="security"]').click();
    const button = page.locator('#inspect-tunnel');
    const result = page.locator('#inspection-result');
    if (['no-tunnel', 'untrusted'].includes(scenario)) {
      assert.equal(await button.isDisabled(), true);
      assert.equal(calls.includes('inspect_tunnel'), false);
    } else {
      await button.click();
      if (scenario === 'late') {
        assert.equal(await button.isDisabled(), true);
        await page.locator('.bottom-nav:visible [data-action="home"], .bottom-nav:visible [data-screen="home"]').click();
        complete();
        await page.waitForFunction(() => document.querySelector('.home-view')?.getClientRects().length > 0);
        await page.waitForFunction(() => window.__diagnosticPending === 0);
        assert.equal(await result.isVisible(), false, 'late evidence must not reopen a closed pane');
        assert.ok(!(await result.textContent()).includes(evidence.rx_bytes), 'late evidence must not update stale pane');
      } else {
        await page.waitForFunction(() => !document.querySelector('#inspect-tunnel')?.disabled);
        const text = await result.textContent();
        assert.ok(!text.includes('SECRET'));
        if (scenario === 'failure') assert.match(text, /ответ отклонён/);
        else if (scenario === 'unavailable') {
          assert.match(text, /Статистика туннеля недоступна/);
          assert.ok(!text.includes(evidence.rx_bytes));
        } else {
          assert.ok(text.includes(evidence.rx_bytes), 'u64 counter must remain exact');
          assert.match(text, scenario === 'english' ? /Traffic protection is unverified/ : /Защита трафика не подтверждена/);
          if (scenario === 'english') assert.doesNotMatch(text, /[А-Яа-яЁё]/);
        }
      }
    }
    assert.notEqual(await page.locator('#orb-label').textContent(), 'Подключено');
    assert.notEqual(await page.locator('#orb-label').textContent(), 'Connected');
    assert.deepEqual(forbidden, []);
    assert.deepEqual(errors, []);
    assert.deepEqual(outbound, []);
    await context.close();
    checks++;
  }
  console.log(JSON.stringify({ diagnostics_scenarios: checks, result: 'PASS', scope: 'synthetic IPC / browser UI only; no native networking tested' }));
} finally {
  await browser.close();
}
