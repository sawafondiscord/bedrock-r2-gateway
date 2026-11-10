import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { verifyProof, configuration } from '../src/worker.js';
const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const pub = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url');
const config = { system: '0123456789abcdef0123', publicKeys: [pub], maxProofAgeSeconds: 60, futureClockSkewSeconds: 5,
  files: { app: { key: 'private/app.zip', downloadName: 'app.zip', allowOutdated: false },
    update: { key: 'private/update.zip', downloadName: 'update.zip', allowOutdated: true },
    premium: { key: 'private/premium.zip', downloadName: 'premium.zip', allowOutdated: false,
      requiredVariable: { name: 'tier', equals: 'premium' } } } };
const now = Math.floor(Date.now() / 1000);
const base = { protocol_version: 'bedrock-v1', system: config.system, response_code: 'OK',
  authed: true, is_error: false, is_failure: false, session_token: 'test-session-not-real', kid: 'test-key',
  challenge: 'a'.repeat(86), server_time: now };
async function sign(p = base, key = pair.privateKey) {
  const bytes = new TextEncoder().encode(typeof p === 'string' ? p : JSON.stringify(p));
  return Buffer.concat([Buffer.from(await crypto.subtle.sign('Ed25519', key, bytes)), Buffer.from(bytes)]).toString('base64url');
}
function env() {
  const calls = [];
  return { GATEWAY_CONFIG: JSON.stringify(config), calls, FILES: { async get(key) {
    calls.push(key); return { body: 'zip-bytes', size: 9, httpEtag: '"etag"' };
  } } };
}
function req(proof, id = 'app', init = {}) {
  return new Request(`https://gateway.example/v1/download/${id}`, {
    method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: proof, ...init
  });
}
test('signed proof accepted; exact R2 bytes streamed with no-store', async () => {
  const e = env(), r = await worker.fetch(req(await sign()), e);
  assert.equal(r.status, 200); assert.equal(await r.text(), 'zip-bytes');
  assert.deepEqual(e.calls, ['private/app.zip']);
  assert.equal(r.headers.get('cache-control'), 'private, no-store');
  assert.equal(r.headers.get('etag'), '"etag"');
});
test('tampering fails before R2 access', async () => {
  const bytes = Buffer.from(await sign(), 'base64url'); bytes[70] ^= 1;
  const e = env(), r = await worker.fetch(req(bytes.toString('base64url')), e);
  assert.equal(r.status, 401); assert.deepEqual(e.calls, []);
});
test('different signing key rejected', async () => {
  const other = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  await assert.rejects(verifyProof(await sign(base, other.privateKey), config, now));
});
for (const [name, fields] of Object.entries({
  'wrong system': { system: 'ffffffffffffffffffff' },
  'wrong protocol': { protocol_version: 'bedrock-v2' },
  'expired': { server_time: now - 61 },
  'future': { server_time: now + 6 },
  'string timestamp': { server_time: String(now) },
  'missing session': { session_token: '' },
  'missing kid': { kid: '' },
  'short challenge': { challenge: 'a' },
  'false authed': { authed: false },
  'string authed': { authed: 'true' },
  'contradictory flags': { is_failure: true },
  'unknown response': { response_code: 'SURPRISE' },
  'terminated': { response_code: 'SESSION_TERMINATED' }
})) test(`rejects ${name}`, async () => {
  const e = env();
  const r = await worker.fetch(req(await sign({ ...base, ...fields })), e);
  assert.equal(r.status, 401); assert.deepEqual(e.calls, []);
});
test('timestamp boundaries accepted', async () => {
  await verifyProof(await sign({ ...base, server_time: now - 60 }), config, now);
  await verifyProof(await sign({ ...base, server_time: now + 5 }), config, now);
});
test('OUTDATED allowed only on configured update file', async () => {
  const p = await sign({ ...base, response_code: 'OUTDATED', is_error: true });
  assert.equal((await worker.fetch(req(p), env())).status, 403);
  assert.equal((await worker.fetch(req(p, 'update'), env())).status, 200);
});
test('signed server-side entitlement required', async () => {
  for (const variables of [undefined, {}, { tier: false }, { tier: 'basic' }, { tier: true }])
    assert.equal((await worker.fetch(req(await sign({ ...base, variables }), 'premium'), env())).status, 403);
  assert.equal((await worker.fetch(req(await sign({ ...base, variables: { tier: 'premium' } }), 'premium'), env())).status, 200);
});
test('unknown file and prototype names never reach R2', async () => {
  for (const id of ['unknown', '__proto__', 'constructor']) {
    const e = env(); assert.equal((await worker.fetch(req(await sign(), id), e)).status, 404);
    assert.deepEqual(e.calls, []);
  }
});
test('oversized stream rejected even without Content-Length', async () => {
  assert.equal((await worker.fetch(req('a'.repeat(65537)), env())).status, 413);
});
test('bad encoding, unsigned JSON and signed non-JSON rejected', async () => {
  for (const proof of ['', '{}', 'a', '!!!!', await sign('not json'), await sign('[]')])
    assert.ok([400, 401].includes((await worker.fetch(req(proof), env())).status));
});
test('key rotation accepts explicitly configured previous key', async () => {
  const other = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const next = Buffer.from(await crypto.subtle.exportKey('raw', other.publicKey)).toString('base64url');
  await verifyProof(await sign(), { ...config, publicKeys: [next, pub] }, now);
});
test('bad config fails closed', async () => {
  for (const patch of [{ publicKeys: [] }, { publicKeys: ['bad'] }, { maxProofAgeSeconds: 999 },
    { files: { app: { ...config.files.app, downloadName: 'bad\r\nheader' } } }]) {
    const e = env(); e.GATEWAY_CONFIG = JSON.stringify({ ...config, ...patch });
    assert.equal((await worker.fetch(req(await sign()), e)).status, 503); assert.deepEqual(e.calls, []);
  }
  assert.throws(() => configuration({ GATEWAY_CONFIG: '{}' }));
});
test('missing R2 object and internal R2 failure', async () => {
  const e = env(); e.FILES.get = async () => null;
  assert.equal((await worker.fetch(req(await sign()), e)).status, 404);
  e.FILES.get = async () => { throw new Error('secret backend details'); };
  const r = await worker.fetch(req(await sign()), e);
  assert.equal(r.status, 500); assert.equal(await r.text(), '{"error":"internal_error"}');
});
test('unsupported methods, media types, ranges and query rejected', async () => {
  const p = await sign();
  assert.equal((await worker.fetch(req(undefined, 'app', { method: 'GET' }), env())).status, 405);
  assert.equal((await worker.fetch(req(p, 'app', { headers: { 'Content-Type': 'application/json' } }), env())).status, 415);
  assert.equal((await worker.fetch(req(p, 'app', { headers: { 'Content-Type': 'text/plain', Range: 'bytes=0-1' } }), env())).status, 400);
  assert.equal((await worker.fetch(req(p, 'app?token=secret'), env())).status, 400);
});
test('stateless replay within the acceptance window is explicitly supported', async () => {
  const p = await sign();
  assert.equal((await worker.fetch(req(p), env())).status, 200);
  assert.equal((await worker.fetch(req(p), env())).status, 200);
});
