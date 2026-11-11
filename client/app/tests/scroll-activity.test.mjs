import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

const source = await readFile(new URL('../src/scroll-activity.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { installScrollActivity } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

function fixture() {
  class FakeElement {
    scrollHeight = 900;
    clientHeight = 400;
    scrollWidth = 380;
    clientWidth = 380;
    classList = new Set();
    constructor() { this.classList.remove = this.classList.delete.bind(this.classList); }
  }
  const events = new Map();
  const timers = new Map();
  let serial = 0;
  const viewEvents = new Map();
  const document = {
    hidden: false,
    scrollingElement: new FakeElement(),
    defaultView: {
      Element: FakeElement,
      setTimeout(callback, delay) { const id = ++serial; timers.set(id, { callback, delay }); return id; },
      clearTimeout(id) { timers.delete(id); },
      addEventListener(type, listener) { viewEvents.set(type, listener); },
      removeEventListener(type) { viewEvents.delete(type); },
    },
    addEventListener(type, listener, options) { events.set(type, { listener, options }); },
    removeEventListener(type) { events.delete(type); },
  };
  const scroll = (target) => events.get('scroll').listener({ target });
  const idle = () => {
    const queued = [...timers.values()];
    timers.clear();
    queued.forEach(({ callback }) => callback());
  };
  return { document, FakeElement, events, viewEvents, timers, scroll, idle };
}

test('idle scrollbar is hidden; actual scroll reveals it for 700ms', () => {
  const f = fixture();
  installScrollActivity(f.document);
  const pane = new f.FakeElement();
  assert.equal(pane.classList.has('is-scrolling'), false);
  f.scroll(pane);
  assert.equal(pane.classList.has('is-scrolling'), true);
  assert.equal([...f.timers.values()][0].delay, 700);
  assert.deepEqual(f.events.get('scroll').options, { capture: true, passive: true });
  f.idle();
  assert.equal(pane.classList.has('is-scrolling'), false);
});

test('ongoing scroll resets its timer and targets stay independent', () => {
  const f = fixture();
  installScrollActivity(f.document);
  const a = new f.FakeElement();
  const b = new f.FakeElement();
  f.scroll(a);
  const oldId = [...f.timers.keys()][0];
  f.scroll(a);
  assert.equal(f.timers.has(oldId), false);
  assert.equal(f.timers.size, 1);
  f.scroll(b);
  assert.equal(f.timers.size, 2);
  f.idle();
  assert.equal(a.classList.has('is-scrolling'), false);
  assert.equal(b.classList.has('is-scrolling'), false);
});

test('document scrolling and dynamically created panes are supported', () => {
  const f = fixture();
  installScrollActivity(f.document);
  f.scroll(f.document);
  assert.equal(f.document.scrollingElement.classList.has('is-scrolling'), true);
  const laterPane = new f.FakeElement();
  f.scroll(laterPane);
  assert.equal(laterPane.classList.has('is-scrolling'), true);
});

test('non-scrollable panes and unrelated targets stay hidden', () => {
  const f = fixture();
  installScrollActivity(f.document);
  const pane = new f.FakeElement();
  pane.scrollHeight = pane.clientHeight;
  f.scroll(pane);
  f.scroll(null);
  assert.equal(f.timers.size, 0);
});

test('visibility changes, page exit and disposal clear pending timers', () => {
  const f = fixture();
  const dispose = installScrollActivity(f.document);
  const pane = new f.FakeElement();
  f.scroll(pane);
  f.document.hidden = true;
  f.events.get('visibilitychange').listener();
  assert.equal(pane.classList.has('is-scrolling'), false);
  assert.equal(f.timers.size, 0);
  f.scroll(pane);
  f.viewEvents.get('pagehide')();
  assert.equal(f.timers.size, 0);
  f.scroll(pane);
  dispose();
  assert.equal(f.timers.size, 0);
  assert.equal(f.events.size, 0);
  assert.equal(f.viewEvents.size, 0);
  assert.equal(pane.classList.has('is-scrolling'), false);
});
