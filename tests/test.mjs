// 実行: node tests/test.mjs （ネットワーク・実ブラウザ不要の範囲）
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import * as W from '../worker.js';
let n = 0; const ok = (m) => console.log('✓', ++n, m);
const py = (code) => spawnSync('python3', ['-c', code]);

// ===== URL検証・SSRF =====
for (const ip of ['127.0.0.1','10.1.2.3','172.16.0.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','198.18.0.1','::1','fd00::1','fe80::1','::ffff:7f00:1']) assert.ok(W.isPrivateIp(ip), ip);
for (const ip of ['8.8.8.8','93.184.216.34','172.32.0.1','2606:4700::1111']) assert.ok(!W.isPrivateIp(ip), ip);
ok('isPrivateIp');
for (const u of ['file:///etc/passwd','javascript:alert(1)','ftp://example.com','http://localhost/','http://127.0.0.1/','http://2130706433/','http://0x7f.1/','http://[::1]/',
  'http://169.254.169.254/latest/meta-data','http://10.0.0.1/','http://u:p@example.com/','http://example.com:22/','http://intranet/','http://x.internal/','http://[::ffff:127.0.0.1]/','data:text/html,x'])
  assert.throws(() => W.checkSync(u), u);
assert.doesNotThrow(() => W.checkSync('https://example.com/a?b=1'));
assert.doesNotThrow(() => W.checkSync('data:image/png;base64,AAAA', true));
ok('checkSync（スキーム・認証情報・ポート・内部ホスト・IP表記ゆれ）');
const pub = async (h, t) => t === 'A' ? ['93.184.216.34'] : [];
await assert.rejects(W.validate('https://evil.example/', false, async (h, t) => t === 'A' ? ['93.184.216.34'] : ['::1']));
await assert.rejects(W.validate('https://evil.example/', false, async () => { throw new Error('dns'); }));
assert.equal(await W.validate('https://ok.example/x', false, pub), 'https://ok.example/x');
ok('validate（DNS結果が内部IP／DNS失敗は拒否）');

// ===== 画像形式の検証 =====
const B = (...a) => Uint8Array.from([...a, ...new Array(16).fill(0)]);
assert.equal(W.sniffImage(B(0x89,0x50,0x4e,0x47)), 'image/png');
assert.equal(W.sniffImage(B(0xff,0xd8,0xff,0xe0)), 'image/jpeg');
assert.equal(W.sniffImage(new TextEncoder().encode('<html><script>alert(1)</script>')), null);
assert.equal(W.sniffImage(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>')), 'image/svg+xml');
assert.equal(W.sniffImage(new TextEncoder().encode('<svg xmlns="x"><script>alert(1)</script></svg>')), null);
assert.equal(W.sniffImage(new TextEncoder().encode('<svg xmlns="x" onload="x()"></svg>')), null);
ok('sniffImage（偽装HTML・スクリプト入りSVGを拒否）');

// ===== Worker ハンドラ（fetchをモック） =====
const realFetch = globalThis.fetch;
const PNG = Uint8Array.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,...new Array(32).fill(1)]);
let routes = {};
globalThis.fetch = async (url, o) => { const r = routes[String(url)]; if (!r) throw new Error('no route ' + url); return typeof r === 'function' ? r(o) : r; };
const dnsOK = (h) => `https://cloudflare-dns.com/dns-query?name=${h}&type=A`;
const dnsRoutes = (h, ip) => ({ [dnsOK(h)]: new Response(JSON.stringify({ Answer: [{ type: 1, data: ip }] })), [`https://cloudflare-dns.com/dns-query?name=${h}&type=AAAA`]: new Response('{}') });
const call = (path, env = {}, headers = {}, opts = { resolve: pub }) => W.handle(new Request('https://app.test' + path, { headers }), env, { waitUntil: p => p.catch?.(() => {}) }, opts);
W._reset();
routes = { 'https://a.example/p.png': () => new Response(PNG, { headers: { 'content-type': 'image/png' } }) };
let r = await call('/api/img?url=' + encodeURIComponent('https://a.example/p.png'));
assert.equal(r.status, 200); assert.equal(r.headers.get('content-type'), 'image/png'); assert.match(r.headers.get('content-security-policy'), /sandbox/);
routes = { 'https://a.example/x.png': () => new Response('<html>nope</html>', { headers: { 'content-type': 'image/png' } }) };
r = await call('/api/img?url=' + encodeURIComponent('https://a.example/x.png')); assert.equal(r.status, 502);
ok('/api/img 正常系・Content-Type偽装の拒否');
routes = { 'https://a.example/r': () => new Response(null, { status: 302, headers: { location: 'http://10.0.0.1/secret.png' } }) };
r = await call('/api/img?url=' + encodeURIComponent('https://a.example/r')); assert.equal(r.status, 502); assert.match((await r.json()).error, /not allowed|blocked/);
routes = { 'https://a.example/r2': () => new Response(null, { status: 302, headers: { location: 'https://rebind.example/a.png' } }) };
r = await call('/api/img?url=' + encodeURIComponent('https://a.example/r2'), {}, {}, { resolve: async (h, t) => h === 'rebind.example' && t === 'A' ? ['192.168.0.5'] : ['93.184.216.34'] });
assert.equal(r.status, 502);
routes = { 'https://a.example/loop': () => new Response(null, { status: 302, headers: { location: 'https://a.example/loop' } }) };
r = await call('/api/img?url=' + encodeURIComponent('https://a.example/loop')); assert.equal(r.status, 502); assert.match((await r.json()).error, /redirect/);
ok('リダイレクト先が内部IP／DNSが内部IP／リダイレクトループを拒否');
routes = { 'https://a.example/big.png': () => new Response(PNG, { headers: { 'content-type': 'image/png', 'content-length': String(30 << 20) } }) };
r = await call('/api/img?url=' + encodeURIComponent('https://a.example/big.png')); assert.equal(r.status, 502);
ok('サイズ上限');
// アクセス制御
assert.equal((await call('/api/img?url=x', { ACCESS_TOKEN: 's3cret' })).status, 401);
assert.equal((await call('/api/img?url=x', { ACCESS_TOKEN: 's3cret' }, { authorization: 'Bearer wrong' })).status, 401);
assert.notEqual((await call('/api/img?url=x', { ACCESS_TOKEN: 's3cret' }, { authorization: 'Bearer s3cret' })).status, 401);
assert.equal((await call('/api/img?url=x', {}, { origin: 'https://evil.test' })).status, 403);
assert.equal((await call('/api/img?url=x', {}, { 'sec-fetch-site': 'cross-site' })).status, 403);
assert.equal((await W.handle(new Request('https://app.test/api/img', { method: 'POST' }), {}, {}, {})).status, 405);
ok('アクセストークン／Origin／メソッド制限');
W._reset();
let last; for (let i = 0; i < 61; i++) last = (await call('/api/page?url=x', {}, { 'cf-connecting-ip': '1.1.1.1' })).status;
assert.equal(last, 429); assert.notEqual((await call('/api/page?url=x', {}, { 'cf-connecting-ip': '2.2.2.2' })).status, 429);
ok('利用者(IP)ごとのレート制限');

// ===== SPA／ページネーション（偽ブラウザでロジックを検証。実ブラウザではない） =====
function fakeBrowser(site) {
  const log = { aborted: [], continued: [], closedPopups: 0, visited: [] }; let cur = null, round = 0, reqH, tc;
  const page = {
    setViewport: async () => {}, setRequestInterception: async () => {}, on(e, f) { if (e === 'request') reqH = f; }, url: () => cur || 'about:blank',
    async goto(u) { log.visited.push(u); cur = u; round = 0; const pg = site[u]; if (!pg) return;
      for (const sub of pg.subreqs || []) { let res = null; await reqH({ url: () => sub, method: () => 'GET', resourceType: () => 'image', redirectChain: () => [], abort: async () => { log.aborted.push(sub); }, continue: async () => { log.continued.push(sub); } }); } },
    async evaluate(fn) { const s = fn.toString(), pg = site[cur];
      if (s.includes('getComputedStyle')) { const r = pg.rounds[Math.min(round, pg.rounds.length - 1)]; return r; }
      if (s.includes('scrollBy')) { round++; return 1000 + round * 100 < 1000 + pg.rounds.length * 100 ? 1000 + round * 100 : 9999; }
      if (s.includes('link[rel')) return pg.next || null; }, close: async () => {} };
  const br = { newPage: async () => page, on(e, f) { if (e === 'targetcreated') tc = f; }, close: async () => { log.closed = true; } };
  br.fireTarget = async () => tc({ page: async () => ({ close: async () => { log.closedPopups++; } }) });
  return { br, log };
}
const site = {
  'https://s.example/1': { rounds: [['https://s.example/a.jpg'], ['https://s.example/a.jpg', 'https://s.example/b.jpg'], ['https://s.example/a.jpg', 'https://s.example/b.jpg', 'https://s.example/c.jpg']], next: 'https://s.example/2', subreqs: ['https://s.example/ok.js', 'http://169.254.169.254/x', 'http://localhost:8080/', 'https://s.example/ok2.png'] },
  'https://s.example/2': { rounds: [['https://s.example/c.jpg', 'https://s.example/d.jpg']], next: 'https://s.example/1' }, // 1に戻るループ
};
{ const { br, log } = fakeBrowser(site), ev = []; const ctl = { aborted: false };
  await W.scan({}, 'https://s.example/1', 5, e => ev.push(e), ctl, { launch: async () => br, resolve: pub, wait: 0 });
  const imgs = ev.filter(e => e.t === 'images');
  const all = imgs.flatMap(e => e.urls);
  assert.deepEqual([...new Set(all)].sort(), ['https://s.example/a.jpg','https://s.example/b.jpg','https://s.example/c.jpg','https://s.example/d.jpg']);
  assert.equal(all.length, 4, '重複送信なし（無限スクロールの増分のみ）');
  assert.deepEqual(log.visited, ['https://s.example/1', 'https://s.example/2'], 'ページネーション・ループ防止');
  assert.deepEqual(log.aborted.sort(), ['http://169.254.169.254/x', 'http://localhost:8080/']);
  assert.deepEqual(log.continued.sort(), ['https://s.example/ok.js', 'https://s.example/ok2.png']);
  await br.fireTarget(); assert.equal(log.closedPopups, 1); assert.ok(log.closed);
  assert.equal(imgs.find(e => e.urls.includes('https://s.example/d.jpg')).page, 2);
  ok('スキャン：無限スクロール増分・ページネーション・ループ防止・サブリソース遮断・ポップアップ閉鎖・ブラウザ終了'); }
{ const { br, log } = fakeBrowser(site), ctl = { aborted: false }, ev = [];
  await W.scan({}, 'https://s.example/1', 1, e => ev.push(e), ctl, { launch: async () => br, resolve: pub, wait: 0 });
  assert.deepEqual(log.visited, ['https://s.example/1'], '最大ページ数の上限'); ok('最大ページ数の上限'); }
{ const { br, log } = fakeBrowser(site), ctl = { aborted: true };
  await W.scan({}, 'https://s.example/1', 5, () => {}, ctl, { launch: async () => br, resolve: pub, wait: 0 });
  assert.equal(log.visited.length, 0); assert.ok(log.closed); ok('中断時はブラウザを閉じて即終了'); }
await assert.rejects(W.scan({}, 'http://127.0.0.1/', 1, () => {}, { aborted: false }, { launch: async () => fakeBrowser(site).br, resolve: pub }));
ok('開始URLが内部アドレスなら拒否');
// 同時実行数
{ W._reset(); const env = {}; let release; const gate = new Promise(r => (release = r));
  const mkOpts = () => ({ resolve: pub, wait: 0, launch: async () => { await gate; return fakeBrowser(site).br; } });
  const get = (ip) => W.handle(new Request('https://app.test/api/scan?url=' + encodeURIComponent('https://s.example/1'), { headers: { 'cf-connecting-ip': ip } }), env, { waitUntil: () => {} }, mkOpts());
  const a = await get('9.9.9.1'), a2 = await get('9.9.9.1'), b = await get('9.9.9.2'), c = await get('9.9.9.3');
  assert.equal(a.status, 200); assert.equal(a2.status, 429, '同一利用者の同時スキャンは1件'); assert.equal(b.status, 200); assert.equal(c.status, 429, '全体上限2件');
  release(); ok('同時実行数の制限（全体・利用者別）'); }
globalThis.fetch = realFetch;

// ===== ZIP整合性・大量画像 =====
const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const code = html.split('//ZIP-START')[1].split('//ZIP-END')[0];
const zipStream = new Function(code + ';return zipStream')();
const mk = (s) => ({ blob: new Blob([s]), url: 'u' });
const bad = { url: 'bad', blob: { stream() { return { getReader() { return { read: () => Promise.reject(new Error('read error')) }; } }; } } };
const big = new Uint8Array(3 << 20).map((_, i) => i * 7);
{ const chunks = []; const sink = { write: async u => { chunks.push(Buffer.from(u)); } };
  const res = await zipStream([mk('hello'), bad, { blob: new Blob([big]), url: 'big' }, mk('日本語')], ['a.txt','b.png','c.bin','あ.txt'], sink, {});
  assert.equal(res.ok, 3); assert.equal(res.failed.length, 1);
  fs.writeFileSync('/tmp/t.zip', Buffer.concat(chunks));
  const p = py(`import zipfile
z=zipfile.ZipFile('/tmp/t.zip');assert z.testzip() is None
assert sorted(z.namelist())==sorted(['a.txt','c.bin','あ.txt','_failed.txt'])
assert z.read('a.txt')==b'hello' and len(z.read('c.bin'))==3<<20 and z.read('あ.txt').decode()=='日本語'
print('ok')`);
  assert.equal(p.stdout.toString().trim(), 'ok', p.stderr.toString()); ok('ZIP整合性（CRC・日本語名・失敗画像の記録）'); }
{ const ac = new AbortController(); ac.abort();
  await assert.rejects(zipStream([mk('x')], ['x'], { write: async () => {} }, { signal: ac.signal }), { name: 'AbortError' }); ok('ZIPキャンセル'); }
{ const N = 5000, fd = fs.openSync('/tmp/many.zip', 'w'); const sink = { write: async u => { fs.writeSync(fd, u); } };
  const list = Array.from({ length: N }, (_, i) => ({ url: 'u' + i, open: async () => new Blob([new Uint8Array(8192).fill(i & 255)]).stream() }));
  const h0 = process.memoryUsage().heapUsed; let peak = 0;
  const res = await zipStream(list, list.map((_, i) => `f${i}.bin`), sink, { onp: () => { peak = Math.max(peak, process.memoryUsage().heapUsed - h0); } });
  fs.closeSync(fd); assert.equal(res.ok, N);
  const p = py(`import zipfile
z=zipfile.ZipFile('/tmp/many.zip');assert z.testzip() is None and len(z.namelist())==5000
assert z.read('f77.bin')==bytes([77])*8192
print('ok')`);
  assert.equal(p.stdout.toString().trim(), 'ok', p.stderr.toString());
  ok(`大量画像ZIP（${N}枚・約40MBをストリーム処理して整合性OK／ヒープ増加ピーク ${(peak / 1048576).toFixed(1)}MB）`); }
console.log('ALL PASSED');
