// Run against a local Vite instance. Playwright may come from the bundled runtime
// through NODE_PATH; no native VPN IPC, profiles or network tunnel are exercised.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const baseURL = process.env.VELUM_UI_TEST_URL || 'http://127.0.0.1:5173';
const output = new URL('../../docs/local/ui-20260928/', import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({
  headless: true,
  channel: process.env.VELUM_TEST_BROWSER_CHANNEL || (process.platform === 'win32' ? 'msedge' : undefined),
});
const page = await browser.newPage();
const errors = [];
page.on('pageerror', error => errors.push(String(error)));

async function checkLayout(label) {
  const result = await page.evaluate(() => {
    const visible = element => element.getBoundingClientRect().width > 0 && element.getBoundingClientRect().height > 0;
    const navs = [...document.querySelectorAll('.bottom-nav')].filter(visible);
    const scrollers = [...document.querySelectorAll('*')].filter(element => {
      const style = getComputedStyle(element);
      return visible(element) && /auto|scroll/.test(style.overflowY) && element.scrollHeight > element.clientHeight + 1;
    });
    return {
      documentOverflow: document.documentElement.scrollWidth > innerWidth + 1 || document.documentElement.scrollHeight > innerHeight + 1,
      navCount: navs.length,
      navVisible: navs.every(nav => {
        const bounds = nav.getBoundingClientRect();
        return bounds.top >= 0 && bounds.bottom <= innerHeight + 1 && bounds.right <= innerWidth + 1;
      }),
      scrollers: scrollers.map(element => element.id || element.className),
      contentOverflow: [...document.querySelectorAll('.screen-content, .home-view')].filter(visible).some(element => element.scrollWidth > element.clientWidth + 1),
    };
  });
  assert.equal(result.documentOverflow, false, `${label}: document must not scroll`);
  assert.equal(result.contentOverflow, false, `${label}: no horizontal content overflow`);
  assert.equal(result.navCount, 1, `${label}: exactly one bottom nav`);
  assert.equal(result.navVisible, true, `${label}: bottom nav visible`);
  assert.ok(result.scrollers.length <= 1, `${label}: nested scrollbars ${result.scrollers.join(', ')}`);
  console.log(`${label}: layout PASS`);
}

try {
  for (const viewport of [{ width: 380, height: 720 }, { width: 380, height: 680 }, { width: 760, height: 800 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport);
    await page.goto(baseURL);
    await page.locator('#orb-label').filter({ hasText: 'Предпросмотр' }).waitFor();
    await checkLayout(`${viewport.width}x${viewport.height} home`);
    if (viewport.height === 720) await page.screenshot({ path: fileURLToPath(new URL('home.png', output)) });

    await page.locator('.home-view [data-action="share"]').click();
    const tabs = page.getByRole('tab');
    assert.deepEqual(await tabs.allTextContents(), ['Соединение', 'Пользователи']);
    const boxes = await tabs.evaluateAll(nodes => nodes.map(node => {
      const box = node.getBoundingClientRect(); return { width: box.width, height: box.height };
    }));
    assert.ok(Math.abs(boxes[0].width - boxes[1].width) < 1, 'tab widths must match');
    assert.equal(boxes[0].height, boxes[1].height, 'tab heights must match');
    await tabs.nth(1).click();
    assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true');
    await checkLayout(`${viewport.width} share users`);
    await tabs.nth(0).click();
    await tabs.nth(0).press('ArrowRight');
    assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true');
    await tabs.nth(1).press('Home');
    assert.equal(await tabs.nth(0).getAttribute('aria-selected'), 'true');
    if (viewport.height === 720) await page.screenshot({ path: fileURLToPath(new URL('share.png', output)) });

    await page.locator('.screen-bottom-nav [data-screen="settings"]').click();
    await checkLayout(`${viewport.width} settings`);
    assert.equal(await page.locator('.settings-list > button:disabled').count(), 0, 'settings rows must open a screen');
    if (viewport.height === 720) await page.screenshot({ path: fileURLToPath(new URL('settings.png', output)) });
    for (const screen of ['application', 'security', 'backup']) {
      await page.locator(`.settings-list [data-screen="${screen}"]`).click();
      assert.equal(await page.locator('#screen-content').getAttribute('data-screen'), screen);
      await checkLayout(`${viewport.width} ${screen}`);
      await page.locator('#screen-back').click();
      assert.equal(await page.locator('#screen-content').getAttribute('data-screen'), 'settings');
    }

    await page.locator('.screen-bottom-nav [data-screen="add"]').click();
    await checkLayout(`${viewport.width} add`);
    if (viewport.height === 720) await page.screenshot({ path: fileURLToPath(new URL('add.png', output)) });

    await page.locator('.screen-bottom-nav [data-screen="home"]').click();
    await page.locator('#split-shortcut').click();
    await page.locator('[data-split="sites"]').click();
    await checkLayout(`${viewport.width} expanded routes`);
    const pane = page.locator('.sheet-content');
    const widthBefore = await pane.evaluate(element => element.clientWidth);
    await pane.evaluate(element => { element.scrollTop = element.scrollHeight; });
    const overflowing = await pane.evaluate(element => element.scrollHeight > element.clientHeight);
    if (overflowing) {
      await page.waitForFunction(() => document.querySelector('.sheet-content')?.classList.contains('is-scrolling'));
      await page.waitForFunction(() => {
        const pane = document.querySelector('.sheet-content');
        return pane && getComputedStyle(pane, '::-webkit-scrollbar-thumb').backgroundColor !== 'rgba(0, 0, 0, 0)';
      });
      await page.waitForFunction(() => !document.querySelector('.sheet-content')?.classList.contains('is-scrolling'));
      await page.waitForFunction(() => getComputedStyle(document.querySelector('.sheet-content'), '::-webkit-scrollbar-thumb').backgroundColor === 'rgba(0, 0, 0, 0)');
    }
    assert.equal(await pane.evaluate(element => element.clientWidth), widthBefore, 'scrollbar must not shift layout');
    await checkLayout(`${viewport.width} scrolled routes`);
  }
  assert.deepEqual(errors, [], 'no uncaught browser errors');
  console.log('UI_SMOKE_OK: 4 viewports, home/share/settings/add/routes; tabs, scroll activity, persistent nav.');
} finally {
  await browser.close();
}
