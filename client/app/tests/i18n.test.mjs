import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

const source = await readFile(new URL('../src/i18n.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const i18n = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

function fixture(stored = null) {
  const reads = [];
  const writes = [];
  const storage = {
    getItem(key) { reads.push(key); return stored; },
    setItem(key, value) { writes.push([key, value]); },
  };
  const document = { documentElement: { lang: '' } };
  return { storage, document, reads, writes };
}

test('language initializes only from the allowlisted preference and updates document.lang', () => {
  const f = fixture('en');
  assert.equal(i18n.initLanguage(f.storage, f.document), 'en');
  assert.equal(i18n.getLanguage(), 'en');
  assert.equal(f.document.documentElement.lang, 'en');
  assert.deepEqual(f.reads, ['velum.language']);
  assert.deepEqual(f.writes, []);
  assert.equal(i18n.t('Настройки'), 'Settings');
  i18n.setLanguage('ru');
  assert.equal(i18n.t('Настройки'), 'Настройки');
  assert.equal(f.document.documentElement.lang, 'ru');
  assert.deepEqual(f.writes, [['velum.language', 'ru']]);
});

test('unknown or malicious language values fall back to ru and never persist arbitrary input', () => {
  for (const value of [null, undefined, 'EN', 'de', '<script>example</script>', {}, 1]) {
    const f = fixture(value);
    assert.equal(i18n.initLanguage(f.storage, f.document), 'ru');
    assert.equal(i18n.setLanguage(value), 'ru');
    assert.deepEqual(f.writes, [['velum.language', 'ru']]);
  }
});

test('blocked storage does not break language selection', () => {
  const f = fixture();
  const blocked = {
    getItem() { throw new Error('storage unavailable'); },
    setItem() { throw new Error('storage unavailable'); },
  };
  assert.equal(i18n.initLanguage(blocked, f.document), 'ru');
  assert.equal(i18n.setLanguage('en'), 'en');
  assert.equal(f.document.documentElement.lang, 'en');
  assert.equal(i18n.t('Назад'), 'Back');
});

test('unknown copy is preserved, parameters stay literal, missing parameters stay visible', () => {
  i18n.initLanguage(null, null);
  i18n.setLanguage('en');
  assert.equal(i18n.t('unregistered source'), 'unregistered source');
  assert.equal(i18n.hasTranslation('unregistered source'), false);
  assert.equal(i18n.t('Профиль отклонён: {error}', { error: '<b>$&{name}</b>' }), 'Profile rejected: <b>$&{name}</b>');
  assert.equal(i18n.t('Модуль закреплён · {platform}'), 'Pinned module · {platform}');
  assert.equal(i18n.t('{protocol} сохранён локально · {count} AWG-параметров', { protocol: 'AmneziaWG', count: 3 }), 'AmneziaWG saved locally · 3 AWG parameters');
  assert.equal(i18n.t('Профиль отклонён: {error}', Object.create({ error: 'inherited' })), 'Profile rejected: {error}');
});

test('all dictionary entries have English copy and identical placeholder contracts', () => {
  const placeholders = (value) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map((match) => match[1]).sort();
  assert.ok(Object.keys(i18n.en).length > 150);
  for (const [key, value] of Object.entries(i18n.en)) {
    assert.ok(value.trim(), `Empty translation for ${key}`);
    assert.doesNotMatch(value, /[А-Яа-яЁё]/u, `Russian text remains in English copy for ${key}`);
    assert.equal(i18n.ru[key], key);
    assert.deepEqual(placeholders(value), placeholders(key), `Placeholder mismatch for ${key}`);
  }
  assert.ok(Object.isFrozen(i18n.en));
  assert.ok(Object.isFrozen(i18n.ru));
});

test('explicit DOM translation skips dynamic data, unknown labels and nested controls', () => {
  class FakeElement {
    constructor(attrs = {}, text = '', childElementCount = 0, excluded = false) {
      this.attrs = new Map(Object.entries(attrs));
      this.textContent = text;
      this.childElementCount = childElementCount;
      this.excluded = excluded;
    }
    getAttribute(name) { return this.attrs.get(name) ?? null; }
    setAttribute(name, value) { this.attrs.set(name, value); }
    closest() { return this.excluded ? this : null; }
  }
  const label = new FakeElement({ 'data-i18n': 'Настройки' }, 'Настройки');
  const user = new FakeElement({ 'data-i18n': 'Настройки' }, 'untouched-profile-name', 0, true);
  const parent = new FakeElement({ 'data-i18n': 'Настройки' }, 'nested-controls', 1);
  const unknown = new FakeElement({ 'data-i18n': 'unknown' }, 'unknown');
  const input = new FakeElement({
    'data-i18n-placeholder': 'Ключ подключения',
    'data-i18n-title': 'Добавить профиль',
    'data-i18n-aria-label': 'Выбрать профиль',
    value: 'synthetic-user-data',
  });
  const unmarked = new FakeElement({}, 'Настройки');
  const root = { querySelectorAll() { return [label, user, parent, unknown, input, unmarked]; } };
  i18n.initLanguage(null, null);
  i18n.setLanguage('en');
  i18n.applyTranslations(root);
  assert.equal(label.textContent, 'Settings');
  assert.equal(user.textContent, 'untouched-profile-name');
  assert.equal(parent.textContent, 'nested-controls');
  assert.equal(unknown.textContent, 'unknown');
  assert.equal(unmarked.textContent, 'Настройки');
  assert.equal(input.getAttribute('placeholder'), 'Connection key');
  assert.equal(input.getAttribute('title'), 'Add a profile');
  assert.equal(input.getAttribute('aria-label'), 'Choose a profile');
  assert.equal(input.getAttribute('value'), 'synthetic-user-data');
  i18n.setLanguage('ru');
  i18n.applyTranslations(root);
  assert.equal(label.textContent, 'Настройки');
});

test('markup helper is safe to import without a browser document', () => {
  assert.equal(i18n.localizeStaticMarkup('<p>Настройки</p>'), '<p>Настройки</p>');
});

test('current static Russian UI copy has dictionary coverage', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const ast = ts.createSourceFile('main.ts', main, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS);
  const candidates = new Set();
  const add = (value) => {
    const text = value.trim();
    if (/[А-Яа-яЁё]/u.test(text)) candidates.add(text);
  };
  const collect = (value, fragment) => {
    if (!/[А-Яа-яЁё]/u.test(value)) return;
    if (/<\/?[A-Za-z][^>]*>/u.test(value)) {
      for (const match of `<fragment>${value}</fragment>`.matchAll(/>([^<>]*)</gu)) add(match[1]);
      for (const match of value.matchAll(/(?:aria-label|title|placeholder)="([^"]+)"/gu)) add(match[1]);
    } else if (!fragment) add(value);
  };
  function visit(node) {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) collect(node.text, false);
    else if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) collect(node.text, true);
    ts.forEachChild(node, visit);
  }
  visit(ast);
  const missing = [...candidates].filter((value) => !i18n.hasTranslation(value));
  assert.deepEqual(missing, [], `Untranslated UI copy:\n${missing.join('\n')}`);
});
