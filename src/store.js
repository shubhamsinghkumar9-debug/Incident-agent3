import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from './util.js';

const DIR = path.resolve(process.env.DATA_DIR || './data', 'runs');
fs.mkdirSync(DIR, { recursive: true });
const runs = new Map();

for (const f of fs.readdirSync(DIR)) {
  if (!f.endsWith('.json')) continue;
  try {
    const st = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
    runs.set(st.runId, st);
  } catch { /* ignore corrupt file */ }
}

export const get = (runId) => runs.get(runId);

/** Durable write (atomic rename) BEFORE the caller responds. */
export function save(st) {
  const file = path.join(DIR, sha256(st.runId) + '.json');
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(st));
  fs.renameSync(tmp, file);
  runs.set(st.runId, st);
}
