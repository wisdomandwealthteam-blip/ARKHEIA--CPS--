// Run with: node --test tests/test_frontend_returns.cjs
// No packages or running backend required. Execute the real bundled script in a
// minimal DOM built from the actual index.html, including ancestor visibility.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const app = fs.readFileSync(path.join(root, 'frontend/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'frontend/index.html'), 'utf8');
const KEY = 'arkheia_last_check_id';

class Element {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.attrs = { ...attrs };
    this.className = attrs.class || '';
    this.value = attrs.value || '';
    this.children = [];
    this.parentElement = null;
    this.listeners = {};
    this.disabled = false;
    this._text = '';
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(' '); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter(x => x && !names.includes(x)).join(' '); },
      contains: name => this.className.split(/\s+/).includes(name),
    };
  }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
  fire(name) {
    if (name === 'click' && this.disabled) throw new Error('click on disabled button');
    for (const fn of this.listeners[name] || []) fn.call(this, { preventDefault() {} });
  }
  appendChild(child) { child.parentElement = this; this.children.push(child); return child; }
  remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(c => c !== this); this.parentElement = null; }
  scrollIntoView() {}
  reportValidity() { return true; }
  cloneNode(deep) {
    const copy = new Element(this.tagName, this.attrs);
    copy.className = this.className; copy.value = this.value;
    if (deep) for (const child of this.children) copy.appendChild(child.cloneNode(true));
    return copy;
  }
  matches(selector) {
    const m = /^\[([^=\]]+)(?:="([^"]*)")?\]$/.exec(selector);
    return !!m && Object.hasOwn(this.attrs, m[1]) && (m[2] === undefined || this.attrs[m[1]] === m[2]);
  }
  querySelectorAll(selector) {
    const found = [];
    const walk = node => { for (const child of node.children) { if (child.matches(selector)) found.push(child); walk(child); } };
    walk(this); return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

function makeDOM() {
  const documentRoot = new Element('document');
  const stack = [documentRoot];
  const voidTags = new Set(['input', 'meta', 'link', 'br', 'hr', 'img']);
  for (const match of html.matchAll(/<!--[\s\S]*?-->|<![^>]*>|<\/?[A-Za-z][^>]*>/g)) {
    const token = match[0];
    if (token.startsWith('<!')) continue;
    if (token.startsWith('</')) { if (stack.length > 1) stack.pop(); continue; }
    const tag = /^<([\w-]+)/.exec(token)[1].toLowerCase();
    const attrs = {};
    for (const a of token.slice(tag.length + 1).matchAll(/([\w-]+)(?:\s*=\s*"([^"]*)")?/g)) attrs[a[1]] = a[2] ?? '';
    const el = new Element(tag, attrs);
    stack[stack.length - 1].appendChild(el);
    if (!voidTags.has(tag) && !token.endsWith('/>')) stack.push(el);
  }
  const ids = {};
  const walk = node => { if (node.attrs.id) ids[node.attrs.id] = node; for (const child of node.children) walk(child); };
  walk(documentRoot);
  ids['account-template'].content = { firstElementChild: ids['account-template'].children[0] };
  ids.jurisdiction.value = 'US';
  const listeners = {};
  const document = {
    getElementById: id => { assert.ok(ids[id], `missing actual element #${id}`); return ids[id]; },
    querySelector: selector => documentRoot.querySelector(selector),
    createElement: tag => new Element(tag),
    addEventListener: (name, fn) => { listeners[name] = fn; },
  };
  return { document, ids, start: () => listeners.DOMContentLoaded() };
}

const response = (status, body = {}) => ({ status, body });
function report(id, changes = {}) {
  return { check_id: id, unlocked: true, findings_count: 0, findings: [], jurisdiction: 'US', jurisdiction_metadata: {}, notice: 'Notice', ...changes };
}
function preview(id, changes = {}) {
  return { check_id: id, unlock_required: true, findings_count: 0, redacted_summary: [], jurisdiction: 'US', jurisdiction_metadata: {}, notice: 'Notice', ...changes };
}
function page({ url = 'https://app.test/', storage = new Map(), blockedRead = false, blockedWrite = false, replies = [] } = {}) {
  const dom = makeDOM();
  let locationURL = new URL(url);
  const requests = [];
  const unexpected = [];
  const location = {
    get href() { return locationURL.href; },
    get search() { return locationURL.search; },
    assign(value) { locationURL = new URL(value, locationURL); },
  };
  const localStorage = {
    getItem(key) { if (blockedRead) throw new Error('blocked'); return storage.has(key) ? storage.get(key) : null; },
    setItem(key, value) { if (blockedWrite) throw new Error('blocked'); storage.set(key, String(value)); },
  };
  const history = { replaceState(_a, _b, value) { locationURL = new URL(value, locationURL); } };
  const fetch = async (url, options) => {
    requests.push({ url, options });
    if (!replies.length) { unexpected.push(url); throw new Error('unexpected fetch: ' + url); }
    const item = replies.shift();
    const value = typeof item === 'function' ? await item(url, options) : await item;
    if (value instanceof Error) throw value;
    return { status: value.status, ok: value.status >= 200 && value.status < 300, text: async () => JSON.stringify(value.body) };
  };
  const window = { ARKHEIA_CONFIG: { apiBase: 'https://api.test' }, location, history };
  const context = vm.createContext({ window, document: dom.document, navigator: {}, localStorage, fetch, URL, URLSearchParams, Date, console });
  vm.runInContext(app, context, { filename: 'frontend/app.js' });
  dom.start();
  return { ...dom, requests, unexpected, storage, get url() { return locationURL; }, click(id) { dom.ids[id].fire('click'); } };
}
async function flush() { for (let i = 0; i < 3; i++) await new Promise(resolve => setImmediate(resolve)); }
function visible(el) { for (let e = el; e; e = e.parentElement) if (e.classList.contains('hidden')) return false; return true; }
function assertNeutral(p) {
  assert.equal(visible(p.ids['lock-unlocked']), false, 'unverified check must not be marked unlocked');
  assert.equal(visible(p.ids['report-card']), false, 'unverified check must not display a report');
}
function urlFor(id, outcome = 'success') {
  const url = new URL('https://app.test/?tab=billing&other=keep#section');
  url.searchParams.set('clearcheck', outcome);
  url.searchParams.set('checkout', outcome);
  url.searchParams.set('check_id', id);
  return url.href;
}

test('503 return offers visible retry; successful storage restores on ordinary reload', async () => {
  const storage = new Map();
  const id = 'chk_return_1';
  const p = page({ url: urlFor(id), storage, replies: [response(503)] });
  await flush();
  assert.equal(storage.get(KEY), id);
  assert.equal(p.ids['p-check-id'].textContent, id);
  assert.equal(visible(p.ids['preview-card']), true);
  assert.equal(visible(p.ids['preview-details']), false);
  assert.equal(visible(p.ids['retry-report-btn']), true);
  assertNeutral(p);
  assert.match(p.ids['lock-status'].textContent, /503/);
  assert.deepEqual([...p.url.searchParams], [['tab', 'billing'], ['other', 'keep']]);
  assert.equal(p.url.hash, '#section');
  const reload = page({ url: p.url.href, storage, replies: [response(402)] });
  await flush();
  assert.equal(reload.requests[0].url, 'https://api.test/api/clearcheck/report/' + id);
  assert.equal(reload.ids['p-check-id'].textContent, id);
  assert.equal(visible(reload.ids['lock-locked']), true);
  assert.equal(visible(reload.ids['check-report-btn']), true);
  assert.equal(visible(reload.ids['retry-report-btn']), false);
  assertNeutral(reload);
});

test('network failure with blocked storage preserves one URL reference and retries safely', async () => {
  const id = 'chk_blocked';
  const p = page({ url: urlFor(id), blockedRead: true, blockedWrite: true, replies: [new Error('network'), response(200, report(id))] });
  await flush();
  assert.equal(p.url.searchParams.get('tab'), 'billing');
  assert.deepEqual(p.url.searchParams.getAll('check_id'), [id]);
  assert.equal(p.url.searchParams.has('clearcheck'), false);
  assert.equal(p.url.searchParams.has('checkout'), false);
  assert.equal(visible(p.ids['retry-report-btn']), true);
  assertNeutral(p);
  p.click('retry-report-btn'); await flush();
  assert.equal(visible(p.ids['retry-report-btn']), false);
  assert.equal(visible(p.ids['lock-unlocked']), true);
  assert.equal(visible(p.ids['report-card']), true);
  const reload = page({ url: p.url.href, blockedRead: true, blockedWrite: true, replies: [response(503)] });
  await flush();
  assert.equal(reload.requests[0].url, 'https://api.test/api/clearcheck/report/' + id);
  assert.equal(visible(reload.ids['retry-report-btn']), true);
  assertNeutral(reload);
});

test('402 then a successful report verifies unlock; checkout return itself does not', async () => {
  const id = 'chk_pending';
  const p = page({ url: urlFor(id), replies: [response(402), response(200, report(id))] });
  await flush();
  assertNeutral(p);
  assert.equal(visible(p.ids['check-report-btn']), true);
  assert.match(p.ids['lock-status'].textContent, /not been confirmed/);
  p.click('check-report-btn'); await flush();
  assert.equal(visible(p.ids['report-card']), true);
  assert.equal(visible(p.ids['lock-unlocked']), true);
  assert.equal(visible(p.ids['retry-report-btn']), false);
});

test('legacy IDs preserve spaces and encoded slash, are text, and survive reload', async () => {
  const id = ' legacy id /<b> ';
  const storage = new Map();
  const p = page({ url: urlFor(id), storage, replies: [response(402)] });
  await flush();
  assert.equal(p.requests[0].url, 'https://api.test/api/clearcheck/report/' + encodeURIComponent(id));
  assert.match(p.requests[0].url, /%2F/);
  assert.equal(p.ids['p-check-id'].textContent, id);
  assert.equal(p.ids['p-check-id'].children.length, 0, 'ID must not be parsed as HTML');
  assert.equal(storage.get(KEY), id);
  assertNeutral(p);
  const reload = page({ storage, replies: [response(402)] });
  await flush();
  assert.equal(reload.requests[0].url, p.requests[0].url);
  assert.equal(reload.ids['p-check-id'].textContent, id);
});

test('only check_already_unlocked checkout code triggers report verification', async () => {
  const id = ' legacy id /a ';
  const p = page({ url: urlFor(id, 'cancelled'), replies: [response(402), response(400, { error: 'check_already_unlocked', detail: 'not proof' }), response(402), response(200, report(id))] });
  await flush();
  p.ids.checkout_email.value = 'secret@example.test';
  p.click('unlock-btn'); await flush();
  assert.equal(p.requests.length, 3);
  assert.equal(p.requests[1].url, 'https://api.test/api/clearcheck/checkout');
  assert.deepEqual(JSON.parse(p.requests[1].options.body), { check_id: id, customer_email: 'secret@example.test' });
  assert.equal(p.requests[2].url, 'https://api.test/api/clearcheck/report/' + encodeURIComponent(id));
  assertNeutral(p);
  p.click('check-report-btn'); await flush();
  assert.equal(visible(p.ids['lock-unlocked']), true);
  assert.equal(visible(p.ids['report-card']), true);
});

test('other checkout 400 codes do not infer payment or leak submitted values', async () => {
  const secret = 'private-customer@example.invalid';
  for (const code of ['invalid_checkout_request', 'some_other_error', null]) {
    const p = page({ url: urlFor('chk_400'), replies: [response(402), response(400, { error: code, detail: 'server echoed ' + secret })] });
    await flush();
    p.ids.checkout_email.value = secret;
    p.click('unlock-btn'); await flush();
    assert.equal(p.requests.length, 2, 'must not retrieve report on unrelated 400');
    assertNeutral(p);
    assert.equal(visible(p.ids['lock-locked']), true);
    assert.doesNotMatch(p.ids['lock-status'].textContent, /private-customer/);
    if (code === 'invalid_checkout_request') assert.match(p.ids['lock-status'].textContent, /invalid_checkout_request/);
    else assert.match(p.ids['lock-status'].textContent, /400/);
    assert.equal(p.url.href.includes(secret), false);
    assert.equal([...p.storage.values()].includes(secret), false);
  }
});

test('unlocked checkout code followed by failed verification offers retry, not unlock', async () => {
  const p = page({ url: urlFor('chk_verify'), replies: [response(402), response(400, {error: 'check_already_unlocked'}), new Error('offline'), response(200, report('chk_verify'))] });
  await flush();
  p.click('unlock-btn'); await flush();
  assertNeutral(p);
  assert.equal(visible(p.ids['retry-report-btn']), true);
  p.click('retry-report-btn'); await flush();
  assert.equal(visible(p.ids['lock-unlocked']), true);
  assert.equal(visible(p.ids['retry-report-btn']), false);
});

test('unverified, malformed, or mismatched 200 report responses never unlock', async () => {
  const id = 'chk_expected';
  for (const body of [report(id, { unlocked: false }), report('chk_other'), {}, null]) {
    const p = page({ url: urlFor(id), replies: [response(200, body)] });
    await flush();
    assertNeutral(p);
    assert.equal(visible(p.ids['retry-report-btn']), true);
  }
});

test('duplicate and blank URL IDs do not fall back to stored references', async () => {
  for (const ids of [['chk_first', 'chk_second'], ['  ']]) {
    const url = new URL('https://app.test/?clearcheck=success&tab=home#anchor');
    for (const id of ids) url.searchParams.append('check_id', id);
    const p = page({ url: url.href, storage: new Map([[KEY, 'chk_old']]) });
    await flush();
    assert.equal(p.requests.length, 0);
    assert.equal(visible(p.ids['redirect-banner']), true);
    assert.equal(p.url.searchParams.get('tab'), 'home');
    assert.deepEqual(p.url.searchParams.getAll('check_id'), []);
    assert.equal(p.url.hash, '#anchor');
    assertNeutral(p);
  }
});

test('URL recovery takes priority over stale storage when writes fail', async () => {
  const storage = new Map([[KEY, 'chk_stale']]);
  const p = page({ url: urlFor('chk_current'), storage, blockedWrite: true, replies: [response(503)] });
  await flush();
  assert.equal(p.requests[0].url, 'https://api.test/api/clearcheck/report/chk_current');
  assert.deepEqual(p.url.searchParams.getAll('check_id'), ['chk_current']);
  const reload = page({ url: p.url.href, storage, blockedWrite: true, replies: [response(402)] });
  await flush();
  assert.equal(reload.requests[0].url, 'https://api.test/api/clearcheck/report/chk_current');
  assertNeutral(reload);
});

test('new preview replaces a retained stale URL reference without storing user inputs', async () => {
  const p = page({ url: urlFor('chk_old'), blockedRead: true, blockedWrite: true, replies: [response(402), response(200, preview('chk_new'))] });
  await flush();
  p.ids.consumer_name.value = 'Sensitive Name';
  p.ids.consumer_email.value = 'sensitive@example.invalid';
  p.ids.ssn_last4.value = '1234';
  p.ids['preview-form'].fire('submit'); await flush();
  assert.equal(p.ids['p-check-id'].textContent, 'chk_new');
  assert.equal(visible(p.ids['preview-details']), true);
  assert.deepEqual(p.url.searchParams.getAll('check_id'), ['chk_new']);
  for (const secret of ['Sensitive Name', 'sensitive@example.invalid', '1234']) assert.equal(p.url.href.includes(secret), false);
  assert.equal(p.storage.size, 0);
  const reload = page({ url: p.url.href, blockedRead: true, blockedWrite: true, replies: [response(402)] });
  await flush();
  assert.equal(reload.requests[0].url, 'https://api.test/api/clearcheck/report/chk_new');
});

test('preview unlock hint alone is verified by a report before showing unlocked', async () => {
  const p = page({ replies: [response(200, preview('chk_hint', { unlock_required: false })), response(503)] });
  p.ids['preview-form'].fire('submit'); await flush();
  assert.equal(p.requests.length, 2);
  assertNeutral(p);
  assert.equal(visible(p.ids['retry-report-btn']), true);
});

test('legacy callback without ID and ordinary reload use saved reference', async () => {
  const storage = new Map([[KEY, ' legacy id ']]);
  const p = page({ url: 'https://app.test/?clearcheck=success&foo=bar', storage, replies: [response(402)] });
  await flush();
  assert.equal(p.requests[0].url, 'https://api.test/api/clearcheck/report/%20legacy%20id%20');
  assert.equal(p.url.searchParams.get('foo'), 'bar');
  assert.equal(p.url.searchParams.has('clearcheck'), false);
  const reload = page({ url: p.url.href, storage, replies: [response(402)] });
  await flush();
  assert.equal(reload.ids['p-check-id'].textContent, ' legacy id ');
});

test('fresh visit with no reference makes no report request', async () => {
  const p = page(); await flush();
  assert.equal(p.requests.length, 0);
  assert.equal(visible(p.ids['preview-card']), false);
});

test('500 and 404 report failures each have an accessible retry that clears on success', async () => {
  for (const status of [500, 404]) {
    const id = 'chk_retry_' + status;
    const p = page({ url: urlFor(id), replies: [response(status), response(200, report(id))] });
    await flush();
    assertNeutral(p);
    assert.equal(visible(p.ids['retry-report-btn']), true);
    p.click('retry-report-btn'); await flush();
    assert.equal(visible(p.ids['retry-report-btn']), false);
    assert.equal(visible(p.ids['lock-unlocked']), true);
    assert.equal(visible(p.ids['report-card']), true);
  }
});

test('dot-segment legacy IDs are not normalized out by the browser URL parser', async () => {
  for (const id of ['.', '..']) {
    const p = page({ url: urlFor(id), replies: [response(402)] });
    await flush();
    const browserPath = new URL(p.requests[0].url).pathname;
    assert.equal(browserPath, '/api/clearcheck/report%2F' + id);
    assert.equal(decodeURIComponent(browserPath), '/api/clearcheck/report/' + id);
    assert.equal(p.ids['p-check-id'].textContent, id);
    assertNeutral(p);
  }
});

test('nonblank validation matches Python whitespace semantics without normalizing keys', async () => {
  const id = '\ufeff'; // JS trim treats BOM as whitespace; Python str.strip does not.
  const p = page({ url: urlFor(id), replies: [response(402)] });
  await flush();
  assert.equal(p.requests[0].url, 'https://api.test/api/clearcheck/report/%EF%BB%BF');
  assert.equal(p.ids['p-check-id'].textContent, id);
  const blank = page({ url: urlFor('\u0085'), storage: new Map([[KEY, 'chk_stale']]) });
  await flush();
  assert.equal(blank.requests.length, 0);
  assertNeutral(blank);
});

test('malformed UTF-16 in storage does not crash initialization or claim unlock', async () => {
  const p = page({ storage: new Map([[KEY, '\ud800']]) });
  await flush();
  assert.equal(p.requests.length, 0);
  assertNeutral(p);
  assert.equal(visible(p.ids['retry-report-btn']), true);
  assert.match(p.ids['lock-status'].textContent, /encode/);
});

test('legacy callback with read-only storage gains a single recoverable URL reference', async () => {
  const id = ' legacy id ';
  const p = page({ url: 'https://app.test/?clearcheck=success&foo=bar', storage: new Map([[KEY, id]]), blockedWrite: true, replies: [response(503)] });
  await flush();
  assert.deepEqual(p.url.searchParams.getAll('check_id'), [id]);
  assert.equal(p.url.searchParams.get('foo'), 'bar');
  const reload = page({ url: p.url.href, blockedRead: true, blockedWrite: true, replies: [response(402)] });
  await flush();
  assert.equal(reload.ids['p-check-id'].textContent, id);
  assertNeutral(reload);
});

test('when storage becomes available a retained URL reference is persisted and removed', async () => {
  const storage = new Map();
  const blocked = page({ url: urlFor('chk_recovered'), storage, blockedWrite: true, replies: [response(503)] });
  await flush();
  const restored = page({ url: blocked.url.href, storage, replies: [response(402)] });
  await flush();
  assert.equal(storage.get(KEY), 'chk_recovered');
  assert.equal(restored.url.searchParams.has('check_id'), false);
  assert.equal(restored.url.searchParams.get('tab'), 'billing');
});

test('late report result cannot unlock a newly created preview', async () => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const p = page({ url: urlFor('chk_old'), replies: [pending, response(200, preview('chk_new'))] });
  p.ids['preview-form'].fire('submit');
  await flush();
  assert.equal(p.ids['p-check-id'].textContent, 'chk_new');
  release(response(200, report('chk_old')));
  await flush();
  assert.equal(visible(p.ids['lock-locked']), true);
  assertNeutral(p);
});

test('late checkout response cannot verify a different preview', async () => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const p = page({ url: urlFor('chk_old'), replies: [response(402), pending, response(200, preview('chk_new'))] });
  await flush();
  p.click('unlock-btn');
  p.ids['preview-form'].fire('submit');
  await flush();
  release(response(400, { error: 'check_already_unlocked' }));
  await flush();
  assert.equal(p.requests.length, 3);
  assert.equal(p.ids['p-check-id'].textContent, 'chk_new');
  assert.equal(visible(p.ids['lock-locked']), true);
  assertNeutral(p);
});

test('untrusted preview and checkout error details never echo sensitive input', async () => {
  const secret = 'Sensitive Name sensitive@example.invalid 1234';
  const p = page({ replies: [response(422, { detail: secret })] });
  p.ids.consumer_name.value = 'Sensitive Name';
  p.ids.consumer_email.value = 'sensitive@example.invalid';
  p.ids.ssn_last4.value = '1234';
  p.ids['preview-form'].fire('submit'); await flush();
  assert.match(p.ids['form-status'].textContent, /422/);
  assert.doesNotMatch(p.ids['form-status'].textContent, /Sensitive Name|sensitive@example|1234/);
  const checkout = page({ url: urlFor('chk_private'), replies: [response(402), response(502, { detail: secret })] });
  await flush();
  checkout.click('unlock-btn'); await flush();
  assert.match(checkout.ids['lock-status'].textContent, /502/);
  assert.doesNotMatch(checkout.ids['lock-status'].textContent, /Sensitive Name|sensitive@example|1234/);
  assertNeutral(checkout);
});
