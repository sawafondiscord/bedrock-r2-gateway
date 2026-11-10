import { readFile, writeFile } from 'node:fs/promises';
import { configuration } from '../src/worker.js';
const raw = await readFile('config.json', 'utf8');
configuration({ GATEWAY_CONFIG: raw });
// JSON string quoting is accepted by dotenv; keep private operational config out of Git.
await writeFile('.dev.vars', `GATEWAY_CONFIG=${JSON.stringify(JSON.stringify(JSON.parse(raw)))}\n`, { mode: 0o600 });
console.log('Wrote .dev.vars for local development.');
