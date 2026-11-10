// No runtime dependencies. Cloudflare Workers Web Crypto + private R2 binding.
const decoder = new TextDecoder('utf-8', { fatal: true });
const MAX_BODY = 65536;
export class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; }
}
const fail = (status, code) => { throw new HttpError(status, code); };
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (v, key) => Object.prototype.hasOwnProperty.call(v, key);
export function decode64(value) {
  if (typeof value !== 'string' || !value.length || value.length > MAX_BODY ||
      !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) fail(401, 'invalid_proof');
  const bare = value.replace(/=+$/, '');
  if (bare.length % 4 === 1) fail(401, 'invalid_proof');
  try {
    const bytes = Uint8Array.from(atob(bare.replace(/-/g, '+').replace(/_/g, '/') +
      '='.repeat((4 - bare.length % 4) % 4)), c => c.charCodeAt(0));
    // Require a canonical encoding, allowing optional conventional padding.
    if (btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== bare)
      fail(401, 'invalid_proof');
    return bytes;
  } catch { fail(401, 'invalid_proof'); }
}

export function configuration(env) {
  let config;
  try { config = JSON.parse(env.GATEWAY_CONFIG); } catch { fail(503, 'configuration_error'); }
  if (!object(config) || typeof config.system !== 'string' || !/^[a-fA-F0-9]{20}$/.test(config.system) ||
      !Array.isArray(config.publicKeys) || config.publicKeys.length < 1 || config.publicKeys.length > 3 ||
      !object(config.files) || !Object.keys(config.files).length ||
      !Number.isInteger(config.maxProofAgeSeconds) || config.maxProofAgeSeconds < 1 || config.maxProofAgeSeconds > 300 ||
      !Number.isInteger(config.futureClockSkewSeconds) || config.futureClockSkewSeconds < 0 || config.futureClockSkewSeconds > 30)
    fail(503, 'configuration_error');
  try { for (const key of config.publicKeys) if (decode64(key).length !== 32) throw new Error(); }
  catch { fail(503, 'configuration_error'); }
  for (const [id, file] of Object.entries(config.files)) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id) || !object(file) || typeof file.key !== 'string' ||
        !file.key.length || typeof file.downloadName !== 'string' || !/^[a-zA-Z0-9_.-]{1,120}$/.test(file.downloadName) ||
        typeof file.allowOutdated !== 'boolean' ||
        (file.requiredVariable !== undefined && (!object(file.requiredVariable) ||
          typeof file.requiredVariable.name !== 'string' || !file.requiredVariable.name.length ||
          typeof file.requiredVariable.equals !== 'string')))
      fail(503, 'configuration_error');
  }
  return config;
}

export async function verifyProof(transport, config, now = Math.floor(Date.now() / 1000)) {
  const bytes = decode64(transport);
  if (bytes.length <= 64) fail(401, 'invalid_proof');
  const signature = bytes.subarray(0, 64), payloadBytes = bytes.subarray(64);
  let valid = false;
  for (const raw of config.publicKeys) {
    const key = await crypto.subtle.importKey('raw', decode64(raw), { name: 'Ed25519' }, false, ['verify']);
    if (await crypto.subtle.verify('Ed25519', key, signature, payloadBytes)) { valid = true; break; }
  }
  if (!valid) fail(401, 'invalid_proof');
  let p;
  try { p = JSON.parse(decoder.decode(payloadBytes)); } catch { fail(401, 'invalid_proof'); }
  // Parse only after verifying the exact, unmodified payload bytes.
  if (!object(p) || p.protocol_version !== 'bedrock-v1' || p.system !== config.system ||
      !['OK', 'OUTDATED'].includes(p.response_code) || p.authed !== true || p.is_failure !== false ||
      p.is_error !== (p.response_code === 'OUTDATED') ||
      typeof p.session_token !== 'string' || !p.session_token.length ||
      typeof p.kid !== 'string' || !p.kid.length ||
      typeof p.challenge !== 'string' || !/^[\x20-\x7e]{64,100}$/.test(p.challenge) ||
      !Number.isSafeInteger(p.server_time)) fail(401, 'invalid_proof');
  if (p.server_time > now + config.futureClockSkewSeconds || now - p.server_time > config.maxProofAgeSeconds)
    fail(401, 'expired_proof');
  return p;
}

async function readProof(request) {
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY)) fail(413, 'proof_too_large');
  if (!request.body) fail(400, 'missing_proof');
  const reader = request.body.getReader();
  const chunks = []; let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY) { await reader.cancel(); fail(413, 'proof_too_large'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const all = new Uint8Array(total); let offset = 0;
  for (const c of chunks) { all.set(c, offset); offset += c.byteLength; }
  try { return decoder.decode(all).trim(); } catch { fail(401, 'invalid_proof'); }
}

function headers() {
  return new Headers({ 'Cache-Control': 'private, no-store', 'CDN-Cache-Control': 'no-store',
    'Cloudflare-CDN-Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
}
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
        fail(400, 'https_required');
      if (url.search) fail(400, 'query_not_supported');
      const match = /^\/v1\/download\/([a-zA-Z0-9_-]{1,64})$/.exec(url.pathname);
      if (!match) fail(404, 'not_found');
      if (request.method !== 'POST') fail(405, 'method_not_allowed');
      if ((request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() !== 'text/plain')
        fail(415, 'use_text_plain');
      if (request.headers.has('range')) fail(400, 'range_not_supported');
      const config = configuration(env);
      const p = await verifyProof(await readProof(request), config);
      const id = match[1];
      if (!own(config.files, id)) fail(404, 'not_found');
      const file = config.files[id];
      if (p.response_code === 'OUTDATED' && !file.allowOutdated) fail(403, 'update_required');
      if (file.requiredVariable) {
        const { name, equals } = file.requiredVariable;
        if (!object(p.variables) || !own(p.variables, name) || p.variables[name] !== equals)
          fail(403, 'not_entitled');
      }
      // Never use a client-supplied object key, URL, bucket, or signing key.
      const stored = await env.FILES.get(file.key);
      if (!stored) fail(404, 'not_found');
      const h = headers();
      h.set('Content-Type', 'application/octet-stream');
      h.set('Content-Disposition', `attachment; filename="${file.downloadName}"`);
      h.set('Content-Length', String(stored.size));
      h.set('ETag', stored.httpEtag);
      return new Response(stored.body, { status: 200, headers: h });
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const h = headers(); h.set('Content-Type', 'application/json');
      if (status === 405) h.set('Allow', 'POST');
      // Do not log proofs, session tokens, payloads, or raw exceptions.
      return new Response(JSON.stringify({ error: status === 500 ? 'internal_error' : error.message }), { status, headers: h });
    }
  }
};
