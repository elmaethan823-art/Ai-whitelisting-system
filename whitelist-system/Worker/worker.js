// language: JavaScript, file: worker.js, target: Cloudflare Workers
// KV binding required: WHITELIST_KV
// Secret required: ADMIN_KEY, HMAC_SECRET
// Routes:
//   POST /auth              { hwid, product }                    -> { ok, token, expires, tier, plan }
//   POST /admin/add         { hwid, product, days, tier, plan } -> { ok, hwid, product, expires }
//   POST /admin/remove      { hwid, product }                   -> { ok }
//   GET  /admin/list        ?product=                           -> { ok, count, keys }
//   POST /admin/revoke-expired                                  -> { ok, removed }
//   GET  /admin/lookup      ?hwid=&product=                     -> { ok, record }
//   POST /admin/update      { hwid, product, days, tier, plan } -> { ok, record }

const TOKEN_TTL = 3600;           // seconds a client token stays valid
const RATE_LIMIT_WINDOW = 60;     // seconds
const RATE_LIMIT_MAX = 20;        // max /auth calls per IP per window

// ---------- helpers ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
      'Cache-Control': 'no-store'
    }
  });
}

async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function rateLimit(env, ip) {
  const key = `rl:auth:${ip}:${Math.floor(now() / RATE_LIMIT_WINDOW)}`;
  const cur = parseInt(await env.WHITELIST_KV.get(key) || '0', 10);
  if (cur >= RATE_LIMIT_MAX) return false;
  await env.WHITELIST_KV.put(key, String(cur + 1), { expirationTtl: RATE_LIMIT_WINDOW * 2 });
  return true;
}

function recordKey(product, hwid) {
  return `hwid:${product}:${hwid}`;
}

async function readJson(request) {
  try { return await request.json(); }
  catch { return null; }
}

function isAdmin(request, env) {
  return request.headers.get('X-Admin-Key') === env.ADMIN_KEY;
}

// ---------- route handlers ----------

async function handleAuth(request, env) {
  const ip = clientIp(request);
  if (!(await rateLimit(env, ip))) {
    return json({ ok: false, error: 'rate_limited' }, 429);
  }

  const body = await readJson(request);
  if (!body) return json({ ok: false, error: 'bad_json' }, 400);

  const { hwid, product } = body;
  if (!hwid || !product) return json({ ok: false, error: 'missing_fields' }, 400);

  const record = await env.WHITELIST_KV.get(recordKey(product, hwid), 'json');
  if (!record) return json({ ok: false, error: 'not_whitelisted' }, 403);

  const t = now();
  if (record.expires && record.expires < t) {
    return json({ ok: false, error: 'expired', expires: record.expires }, 403);
  }
  if (record.banned) {
    return json({ ok: false, error: 'banned' }, 403);
  }

  const token = await hmacSign(env.HMAC_SECRET, `${hwid}:${product}:${t}`);
  const expires = t + TOKEN_TTL;

  // best-effort last-seen update; ignore failures
  try {
    await env.WHITELIST_KV.put(recordKey(product, hwid), JSON.stringify({
      ...record,
      last_seen: t,
      last_ip: ip
    }));
  } catch (_) {}

  return json({
    ok: true,
    token,
    expires,
    tier: record.tier || 'standard',
    plan: record.plan || 'basic'
  });
}

async function handleAdd(request, env) {
  const body = await readJson(request);
  if (!body) return json({ ok: false, error: 'bad_json' }, 400);

  const { hwid, product, days, tier, plan, banned } = body;
  if (!hwid || !product) return json({ ok: false, error: 'missing_fields' }, 400);

  const t = now();
  const expires = days ? t + days * 86400 : 0;

  const record = {
    expires,
    tier: tier || 'standard',
    plan: plan || 'basic',
    banned: !!banned,
    added: t,
    last_seen: 0,
    last_ip: ''
  };

  await env.WHITELIST_KV.put(recordKey(product, hwid), JSON.stringify(record));
  return json({ ok: true, hwid, product, record });
}

async function handleUpdate(request, env) {
  const body = await readJson(request);
  if (!body) return json({ ok: false, error: 'bad_json' }, 400);

  const { hwid, product, days, tier, plan, banned } = body;
  if (!hwid || !product) return json({ ok: false, error: 'missing_fields' }, 400);

  const existing = await env.WHITELIST_KV.get(recordKey(product, hwid), 'json');
  if (!existing) return json({ ok: false, error: 'not_found' }, 404);

  const t = now();
  const record = {
    ...existing,
    expires: days !== undefined ? (days ? t + days * 86400 : 0) : existing.expires,
    tier: tier !== undefined ? tier : existing.tier,
    plan: plan !== undefined ? plan : existing.plan,
    banned: banned !== undefined ? !!banned : existing.banned,
    updated: t
  };

  await env.WHITELIST_KV.put(recordKey(product, hwid), JSON.stringify(record));
  return json({ ok: true, hwid, product, record });
}

async function handleRemove(request, env) {
  const body = await readJson(request);
  if (!body) return json({ ok: false, error: 'bad_json' }, 400);

  const { hwid, product } = body;
  if (!hwid || !product) return json({ ok: false, error: 'missing_fields' }, 400);

  await env.WHITELIST_KV.delete(recordKey(product, hwid));
  return json({ ok: true, hwid, product });
}

async function handleList(url, env) {
  const product = url.searchParams.get('product');
  const prefix = product ? `hwid:${product}:` : 'hwid:';
  const list = await env.WHITELIST_KV.list({ prefix });
  const keys = list.keys.map(k => k.name);
  return json({ ok: true, count: keys.length, keys, truncated: list.list_complete === false });
}

async function handleLookup(url, env) {
  const hwid = url.searchParams.get('hwid');
  const product = url.searchParams.get('product');
  if (!hwid || !product) return json({ ok: false, error: 'missing_fields' }, 400);

  const record = await env.WHITELIST_KV.get(recordKey(product, hwid), 'json');
  if (!record) return json({ ok: false, error: 'not_found' }, 404);
  return json({ ok: true, hwid, product, record });
}

async function handleRevokeExpired(env) {
  const list = await env.WHITELIST_KV.list({ prefix: 'hwid:' });
  const t = now();
  let removed = 0;
  for (const k of list.keys) {
    const rec = await env.WHITELIST_KV.get(k.name, 'json');
    if (rec && rec.expires && rec.expires < t) {
      await env.WHITELIST_KV.delete(k.name);
      removed++;
    }
  }
  return json({ ok: true, removed });
}

// ---------- entry ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key'
        }
      });
    }

    // public route
    if (path === '/auth') {
      if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
      return handleAuth(request, env);
    }

    if (path === '/' || path === '/health') {
      return json({ ok: true, service: 'whitelist-worker', time: now() });
    }

    // everything below requires admin key
    if (path.startsWith('/admin/')) {
      if (!isAdmin(request, env)) return json({ ok: false, error: 'unauthorized' }, 401);

      try {
        if (path === '/admin/add' && request.method === 'POST')            return await handleAdd(request, env);
        if (path === '/admin/update' && request.method === 'POST')         return await handleUpdate(request, env);
        if (path === '/admin/remove' && request.method === 'POST')         return await handleRemove(request, env);
        if (path === '/admin/list' && request.method === 'GET')            return await handleList(url, env);
        if (path === '/admin/lookup' && request.method === 'GET')          return await handleLookup(url, env);
        if (path === '/admin/revoke-expired' && request.method === 'POST') return await handleRevokeExpired(env);
      } catch (e) {
        return json({ ok: false, error: 'internal', detail: String(e && e.message || e) }, 500);
      }

      return json({ ok: false, error: 'not_found' }, 404);
    }

    return json({ ok: false, error: 'not_found' }, 404);
  }
};
