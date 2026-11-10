// Usage: node examples/download.mjs https://gateway.example app-package proof.txt app.zip
// proof.txt is the original base64url response body, NOT decoded/re-serialized JSON.
import { readFile, open, rename, unlink } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { randomUUID } from 'node:crypto';
import { resolve, dirname, basename, join } from 'node:path';
const [base, fileId, proofPath, output] = process.argv.slice(2);
if (!base || !/^[a-zA-Z0-9_-]{1,64}$/.test(fileId || '') || !proofPath || !output)
  throw new Error('Usage: node examples/download.mjs HTTPS_GATEWAY FILE_ID PROOF_FILE OUTPUT');
const url = new URL(base);
if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/')
  throw new Error('Use an HTTPS gateway origin without credentials, query, or path.');
url.pathname = `/v1/download/${fileId}`;
const proof = (await readFile(proofPath, 'utf8')).trim();
if (!proof.length || Buffer.byteLength(proof) > 65536) throw new Error('Invalid proof size');
const response = await fetch(url, {
  method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: proof,
  redirect: 'error', signal: AbortSignal.timeout(300000)
});
if (response.status !== 200 || !response.body)
  throw new Error(`Gateway rejected download: HTTP ${response.status}`);
const target = resolve(output);
const temporary = join(dirname(target), `.${basename(target)}.${randomUUID()}.part`);
try {
  const handle = await open(temporary, 'wx', 0o600);
  await pipeline(Readable.fromWeb(response.body), handle.createWriteStream());
  // Run the application's release-signature/hash check here before installation.
  await rename(temporary, target);
  console.log(`Downloaded ${basename(target)}. No file was executed.`);
} catch (error) {
  await unlink(temporary).catch(() => {});
  throw error;
}
