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
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(st), 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
  // Persist the directory entry as well as file contents where supported.
  let dirFd;
  try {
    dirFd = fs.openSync(DIR, 'r');
    fs.fsyncSync(dirFd);
  } catch {
    // Some filesystems (notably certain mounted volumes) do not support
    // fsync on directories; the atomic rename still protects file contents.
  } finally {
    if (dirFd !== undefined) fs.closeSync(dirFd);
  }
  runs.set(st.runId, st);
}
