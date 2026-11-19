// Image Extractor v3 - Cloudflare Workers（Browser Rendering + 静的アセット）
const UA = 'Mozilla/5.0 (compatible; ImageExtractor/3.0)';
const MAX_PAGE = 5 << 20, MAX_IMG = 25 << 20, MAX_SVG = 2 << 20, MAX_REQ = 400, MAX_IMAGES = 500;
const TOTAL_MS = 90000, PER_PAGE_MS = 30000, MAX_SCANS = 2;
const LIM = { scan: 6, img: 900, page: 60 }; // 1分あたり・利用者(IP)ごと

// ---------- SSRF対策 ----------
export function isPrivateIp(ip) {
  ip = ip.toLowerCase();
  if (ip.includes(':')) return ip === '::' || ip === '::1' || /^(::ffff:|64:ff9b:|f[cd]|fe[89ab]|2001:db8)/.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || b === 0)) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19));
}
export function checkSync(raw, sub = false) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('invalid url'); }
  if (sub && /^(data:|blob:|about:)/.test(u.protocol)) return u;
  if (!/^https?:$/.test(u.protocol)) throw new Error('scheme not allowed');
  if (u.username || u.password) throw new Error('credentials not allowed');
  if (u.port && !['80', '443'].includes(u.port)) throw new Error('port not allowed');
  const h = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || /\.(localhost|local|internal|lan|home|corp)$/.test(h) || (!h.includes('.') && !h.includes(':'))) throw new Error('host not allowed');
  if ((/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':')) && isPrivateIp(h)) throw new Error('blocked address');
  return u;
}
const isIpLit = h => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':');
async function doh(name, type) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error('dns failed');
  const j = await r.json();
  return (j.Answer || []).filter(a => a.type === (type === 'A' ? 1 : 28)).map(a => a.data);
}
export async function validate(raw, sub = false, resolve = doh) {
  const u = checkSync(raw, sub);
  if (!/^https?:$/.test(u.protocol)) return u.href;
  const h = u.hostname.replace(/^\[|\]$/g, '');
  if (!isIpLit(h)) {
    const ips = [...await resolve(h, 'A'), ...await resolve(h, 'AAAA')]; // 失敗時は例外＝拒否（fail closed）
    if (ips.some(isPrivateIp)) throw new Error('blocked address');
  }
  return u.href;
}
async function safeFetch(raw, resolve, hops = 5) { // リダイレクトは1ホップごとに再検証
  let u = raw;
  for (let i = 0; i <= hops; i++) {
    const url = await validate(u, false, resolve);
    const r = await fetch(url, { redirect: 'manual', headers: { 'User-Agent': UA, Accept: '*/*' }, signal: AbortSignal.timeout(15000) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { r.body?.cancel(); u = new URL(loc, url).href; continue; }
    if (!r.ok) { r.body?.cancel(); throw new Error('status ' + r.status); }
    return r;
  }
  throw new Error('too many redirects');
}
async function readLimited(r, max) {
  if (+r.headers.get('content-length') > max) { r.body?.cancel(); throw new Error('too large'); }
  const rd = r.body.getReader(), chunks = []; let n = 0;
  for (;;) {
    const { done, value } = await rd.read(); if (done) break;
    n += value.length; if (n > max) { rd.cancel(); throw new Error('too large'); }
    chunks.push(value);
  }
  const out = new Uint8Array(n); let o = 0; for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

// ---------- ファイル形式の検証（Content-Typeを信用せず中身で判定） ----------
const asc = (b, s, e) => String.fromCharCode(...b.subarray(s, e));
export function svgSafe(t) { return !/<script|javascript:|\bon\w+\s*=|<foreignobject|<iframe|<!entity|<embed|<object/i.test(t); }
export function sniffImage(b) {
  if (b.length < 12) return null;
  if (b[0] === 0x89 && asc(b, 1, 4) === 'PNG') return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (asc(b, 0, 4) === 'GIF8') return 'image/gif';
  if (asc(b, 0, 4) === 'RIFF' && asc(b, 8, 12) === 'WEBP') return 'image/webp';
  if (asc(b, 4, 8) === 'ftyp' && /avif|avis/.test(asc(b, 8, 16))) return 'image/avif';
  if (b[0] === 0x42 && b[1] === 0x4d) return 'image/bmp';
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return 'image/x-icon';
  if (/<svg[\s>]/.test(new TextDecoder().decode(b.subarray(0, 1024)).toLowerCase())) {
    if (b.length > MAX_SVG || !svgSafe(new TextDecoder().decode(b))) return null;
    return 'image/svg+xml';
  }
  return null;
}

// ---------- レート制限・アクセス制御 ----------
const win = new Map();
export function localLimit(key, max, now = Date.now()) { // Isolate内の簡易固定窓（best-effort）
  if (win.size > 5000) win.clear();
  const w = win.get(key);
  if (!w || now - w.t >= 60000) { win.set(key, { t: now, n: 1 }); return true; }
  return ++w.n <= max;
}
export const _reset = () => { win.clear(); activeScans = 0; ipScans.clear(); };
async function allowed(env, ip, kind) {
  if (!localLimit(kind + ':' + ip, LIM[kind])) return false;
  if (env.RATE_LIMITER) { try { return (await env.RATE_LIMITER.limit({ key: ip })).success; } catch {} } // 任意：Workers Rate Limiting バインディング
  return true;
}
function ctEq(a, b) { let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; }
function authOk(env, req) {
  if (!env.ACCESS_TOKEN) return true;
  const h = req.headers.get('authorization') || '';
  return ctEq(h.startsWith('Bearer ') ? h.slice(7) : req.headers.get('x-access-token') || '', env.ACCESS_TOKEN);
}
let activeScans = 0; const ipScans = new Set();

// ---------- SPA スキャン ----------
const collect = () => {
  const o = new Set(), add = u => { try { u = new URL(String(u).trim(), location.href).href; } catch { return; }
    if (/^https?:/.test(u) || (u.startsWith('data:image') && u.length < 300000)) o.add(u); };
  const best = s => { let b, v = -1; (s || '').split(/,\s+|,(?=\S+\s+\d)/).forEach(c => { const m = c.trim().match(/^(\S+)(?:\s+(\d+(?:\.\d+)?)[wx])?/); if (m && +(m[2] || 1) > v) { v = +(m[2] || 1); b = m[1]; } }); return b; };
  document.querySelectorAll('img,source').forEach(e => { const s = e.currentSrc || best(e.srcset || e.dataset.srcset) || e.getAttribute('src') || e.dataset.src || e.dataset.lazySrc || e.dataset.original; if (s) add(s); });
  let n = 0; for (const e of document.querySelectorAll('body *')) { if (++n > 5000) break;
    const b = getComputedStyle(e).backgroundImage; if (b && b !== 'none') { const re = /url\((['"]?)(.*?)\1\)/g; let m; while ((m = re.exec(b))) add(m[2]); } }
  document.querySelectorAll('meta[property="og:image"],meta[name="twitter:image"]').forEach(m => m.content && add(m.content));
  return [...o];
};
const findNext = () => {
  const ok = h => { try { const u = new URL(h, location.href); return u.origin === location.origin && u.href !== location.href ? u.href : null; } catch { return null; } };
  const rel = document.querySelector('link[rel~=next],a[rel~=next]'); if (rel) { const r = ok(rel.href); if (r) return r; }
  const re = /^\s*(次へ|次のページ|次|もっと見る|next|next page|older|›|»|>|→)\s*$/i;
  for (const a of document.querySelectorAll('a[href]')) { const t = (a.getAttribute('aria-label') || a.textContent || '').trim(); if (re.test(t)) { const r = ok(a.href); if (r) return r; } }
  return null;
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const defaultLaunch = async env => { if (!env.BROWSER) throw new Error('BROWSER binding が未設定です（wrangler.toml を確認）'); const { default: p } = await import('@cloudflare/puppeteer'); return p.launch(env.BROWSER); };

export async function scan(env, start, maxPages, send, ctl = { aborted: false }, opts = {}) {
  const memo = new Map(), base = opts.resolve || doh; // 同一スキャン内のDNS結果をキャッシュ
  const resolve = (h, t) => { const k = h + '|' + t; if (!memo.has(k)) memo.set(k, base(h, t)); return memo.get(k); };
  const t0 = Date.now(), all = new Set(), visited = new Set(), found = new Set();
  const hard = setTimeout(() => { ctl.aborted = true; }, TOTAL_MS + 5000);
  const browser = await (opts.launch || defaultLaunch)(env);
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 900 });
    // 新しいタブ・ポップアップは検証対象外になるため即座に閉じる（迂回防止）
    browser.on('targetcreated', async t => { try { const p = await t.page(); if (p && p !== page) await p.close(); } catch {} });
    page.on('popup', p => { Promise.resolve(p.close()).catch(() => {}); });
    page.on('dialog', d => { Promise.resolve(d.dismiss()).catch(() => {}); });
    let reqs = 0;
    await page.setRequestInterception(true);
    page.on('request', async req => { // ナビゲーション・リダイレクト・サブリソースの全てを1件ずつ検証
      const ab = () => Promise.resolve(req.abort('blockedbyclient')).catch(() => {});
      try {
        if (++reqs > MAX_REQ || req.method() !== 'GET' || req.redirectChain().length > 5) return await ab();
        if (['font', 'media', 'websocket', 'eventsource', 'manifest'].includes(req.resourceType())) return await ab();
        await validate(req.url(), true, resolve);
        await req.continue();
      } catch { await ab(); }
    });
    page.on('response', r => { try { if ((r.headers()['content-type'] || '').startsWith('image/') && r.status() === 200 && /^https?:/.test(r.url())) found.add(r.url()); } catch {} });
    let url = start;
    for (let p = 1; p <= maxPages && url && !ctl.aborted && Date.now() - t0 < TOTAL_MS; p++) {
      visited.add(url);
      send({ t: 'progress', msg: `ページ${p}/${maxPages} を読み込み中…` });
      await validate(url, false, resolve);
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {});
      if (page.url() === 'about:blank') throw new Error('ページを開けませんでした（ブロックまたはタイムアウト）');
      const pageEnd = Math.min(Date.now() + PER_PAGE_MS, t0 + TOTAL_MS);
      let idle = 0, h0 = 0;
      for (let i = 0; i < 60 && !ctl.aborted && Date.now() < pageEnd && all.size < MAX_IMAGES && idle < 3; i++) {
        const urls = [...new Set([...await page.evaluate(collect), ...found])].map(u => u.split('#')[0]).filter(u => !all.has(u)).slice(0, MAX_IMAGES - all.size);
        urls.forEach(u => all.add(u));
        if (urls.length) send({ t: 'images', page: p, urls });
        const h = await page.evaluate(() => { window.scrollBy(0, innerHeight * 0.9); return document.documentElement.scrollHeight; });
        idle = !urls.length && h === h0 ? idle + 1 : 0; h0 = h;
        send({ t: 'progress', msg: `ページ${p}/${maxPages} スクロール中（検出 ${all.size}件）` });
        await sleep(opts.wait ?? 700);
      }
      const next = await page.evaluate(findNext).catch(() => null);
      url = next && !visited.has(next) ? next : null;
    }
    send({ t: 'progress', msg: ctl.aborted ? 'スキャンを中断しました' : `スキャン完了（${all.size}件）` });
  } finally { clearTimeout(hard); await Promise.resolve(browser.close()).catch(() => {}); }
}

// ---------- ルーティング ----------
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
export async function handle(req, env, ctx, opts = {}) {
  const u = new URL(req.url);
  if (!u.pathname.startsWith('/api/')) return env.ASSETS ? env.ASSETS.fetch(req) : json({ error: 'not found' }, 404);
  if (req.method !== 'GET') return json({ error: 'method not allowed' }, 405);
  const o = req.headers.get('origin');
  if ((o && o !== u.origin) || req.headers.get('sec-fetch-site') === 'cross-site') return json({ error: 'forbidden' }, 403);
  if (!authOk(env, req)) return json({ error: 'unauthorized' }, 401);
  const ip = req.headers.get('cf-connecting-ip') || 'local';
  const kind = u.pathname === '/api/scan' ? 'scan' : u.pathname === '/api/img' ? 'img' : 'page';
  if (!await allowed(env, ip, kind)) return json({ error: 'rate limit（リクエストが多すぎます）' }, 429);
  const target = u.searchParams.get('url') || '', resolve = opts.resolve || doh;
  try {
    if (u.pathname === '/api/page') {
      const r = await safeFetch(target, resolve);
      if (!/html/i.test(r.headers.get('content-type') || '')) { r.body?.cancel(); throw new Error('not html'); }
      return json({ url: target, html: new TextDecoder().decode(await readLimited(r, MAX_PAGE)) });
    }
    if (u.pathname === '/api/img') {
      const buf = await readLimited(await safeFetch(target, resolve), MAX_IMG), type = sniffImage(buf);
      if (!type) throw new Error('unsupported or unsafe image');
      return new Response(buf, { headers: { 'Content-Type': type, 'Content-Security-Policy': "sandbox; default-src 'none'", 'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin', 'Cache-Control': 'no-store' } });
    }
    if (u.pathname === '/api/scan') {
      const pages = Math.min(Math.max(+u.searchParams.get('pages') || 1, 1), 10);
      await validate(target, false, resolve);
      if (activeScans >= MAX_SCANS || ipScans.has(ip)) return json({ error: '同時実行数の上限です。しばらくしてから再試行してください' }, 429);
      activeScans++; ipScans.add(ip);
      const { readable, writable } = new TransformStream(), w = writable.getWriter(), te = new TextEncoder(), ctl = { aborted: false };
      req.signal?.addEventListener('abort', () => { ctl.aborted = true; });
      const send = x => w.write(te.encode(JSON.stringify(x) + '\n')).catch(() => { ctl.aborted = true; });
      ctx.waitUntil((async () => {
        try { await scan(env, target, pages, send, ctl, opts); send({ t: 'done' }); }
        catch (e) { send({ t: 'error', msg: String(e.message || e) }); }
        finally { activeScans--; ipScans.delete(ip); await w.close().catch(() => {}); }
      })());
      return new Response(readable, { headers: { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
    }
    return json({ error: 'not found' }, 404);
  } catch (e) { return json({ error: String(e.message || e) }, 502); }
}
export default { fetch: (req, env, ctx) => handle(req, env, ctx) };
