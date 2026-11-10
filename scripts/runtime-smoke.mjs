import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import assert from 'node:assert/strict';
const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const publicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url');
const config = { system: '0123456789abcdef0123', publicKeys: [publicKey], maxProofAgeSeconds: 60,
  futureClockSkewSeconds: 5, files: { app: { key: 'test.bin', downloadName: 'test.bin', allowOutdated: false } } };
const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, scriptPath: 'dist/worker.js', compatibilityDate: '2026-11-01',
  bindings: { GATEWAY_CONFIG: JSON.stringify(config) }, r2Buckets: ['FILES'] }));
try {
  const bucket = await mf.getR2Bucket('FILES');
  await bucket.put('test.bin', 'local-workerd-smoke');
  const payload = new TextEncoder().encode(JSON.stringify({ protocol_version: 'bedrock-v1', system: config.system,
    response_code: 'OK', authed: true, is_error: false, is_failure: false, session_token: 'test-only',
    kid: 'test-key', challenge: 'c'.repeat(86), server_time: Math.floor(Date.now() / 1000) }));
  const sig = await crypto.subtle.sign('Ed25519', pair.privateKey, payload);
  const proof = Buffer.concat([Buffer.from(sig), Buffer.from(payload)]).toString('base64url');
  const request = { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: proof };
  const response = await mf.dispatchFetch('https://gateway.example/v1/download/app', request);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'local-workerd-smoke');
  assert.equal(response.headers.get('cache-control'), 'private, no-store');
  const denied = await mf.dispatchFetch('https://gateway.example/v1/download/app', { ...request, body: 'invalid' });
  assert.equal(denied.status, 401);
  console.log('PASS: local Workers runtime verifies Ed25519 and streams private R2 content; invalid proof rejected.');
} finally { await mf.dispose(); }
