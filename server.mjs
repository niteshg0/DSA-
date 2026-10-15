import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const usersDir = path.join(root, 'users');
const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || '0.0.0.0';
const ID_RE = /^[0-9]{8,15}_[A-Za-z0-9_-]{1,40}$/;
const MAX_BODY = 1024 * 1024;

// Storage: a private GitHub repo when GITHUB_TOKEN + GITHUB_REPO are set, otherwise ./users
const GH_TOKEN = process.env.GITHUB_TOKEN || '';
const GH_REPO = process.env.GITHUB_REPO || ''; // "owner/repo"
const GH_BRANCH = process.env.GITHUB_BRANCH || 'main';
const GH_DIR = process.env.GITHUB_DIR || 'users';
const FLUSH_MS = Number(process.env.FLUSH_MS) || 5000; // batch progress saves into one commit
const USE_GITHUB = Boolean(GH_TOKEN && GH_REPO);

const cache = new Map();   // id -> { rec, sha } (sha is the GitHub file version)
const pending = new Map(); // id -> flush timer
const writing = new Set();

function validId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

/* ---------- local folder storage ---------- */

function localPath(id) {
  return path.join(usersDir, id + '.json');
}

function localRead(id) {
  const file = localPath(id);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function localWrite(rec) {
  fs.mkdirSync(usersDir, { recursive: true });
  fs.writeFileSync(localPath(rec.id), JSON.stringify(rec, null, 2));
}

/* ---------- GitHub storage ---------- */

function ghUrl(id) {
  return 'https://api.github.com/repos/' + GH_REPO + '/contents/' + GH_DIR + '/' + encodeURIComponent(id) + '.json';
}

async function gh(url, opts) {
  return fetch(url, {
    ...opts,
    headers: {
      Authorization: 'Bearer ' + GH_TOKEN,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'dsa-tracker',
      ...(opts && opts.headers),
    },
  });
}

async function ghRead(id) {
  const res = await gh(ghUrl(id) + '?ref=' + encodeURIComponent(GH_BRANCH));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + ')');
  const data = await res.json();
  const rec = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));
  return { rec, sha: data.sha };
}

async function ghWrite(entry, retried) {
  const body = {
    message: 'Update ' + entry.rec.id,
    content: Buffer.from(JSON.stringify(entry.rec, null, 2)).toString('base64'),
    branch: GH_BRANCH,
  };
  if (entry.sha) body.sha = entry.sha;
  const res = await gh(ghUrl(entry.rec.id), { method: 'PUT', body: JSON.stringify(body) });
  if ((res.status === 409 || res.status === 422) && !retried) {
    // our copy of the file version is stale; fetch the latest and overwrite with our record
    const latest = await ghRead(entry.rec.id);
    entry.sha = latest ? latest.sha : undefined;
    return ghWrite(entry, true);
  }
  if (!res.ok) throw new Error('GitHub write failed (' + res.status + '): ' + (await res.text()).slice(0, 200));
  const data = await res.json();
  entry.sha = data.content.sha;
}

async function flush(id) {
  clearTimeout(pending.get(id));
  pending.delete(id);
  const entry = cache.get(id);
  if (!entry) return true;
  if (writing.has(id)) { queueFlush(id); return true; }
  writing.add(id);
  try {
    await ghWrite(entry);
    return true;
  } catch (err) {
    console.error(err.message);
    queueFlush(id); // try again later; the record stays in memory
    return false;
  } finally {
    writing.delete(id);
  }
}

function queueFlush(id) {
  if (pending.has(id)) return;
  pending.set(id, setTimeout(() => flush(id), FLUSH_MS));
}

/* ---------- storage API used by the routes ---------- */

async function readUser(id) {
  if (!validId(id)) return null;
  if (!USE_GITHUB) return localRead(id);
  if (cache.has(id)) return cache.get(id).rec;
  const found = await ghRead(id);
  if (!found) return null;
  cache.set(id, found);
  return found.rec;
}

async function writeUser(rec, { now = false } = {}) {
  if (!validId(rec.id)) throw new Error('Invalid account id');
  if (!USE_GITHUB) { localWrite(rec); return; }
  const entry = cache.get(rec.id) || {};
  entry.rec = rec;
  cache.set(rec.id, entry);
  if (!now) { queueFlush(rec.id); return; }
  if (await flush(rec.id)) return;
  if (!entry.sha) { // never reached GitHub: forget it so the account isn't half-created
    clearTimeout(pending.get(rec.id));
    pending.delete(rec.id);
    cache.delete(rec.id);
  }
  throw new Error('Could not save to GitHub. Check the server log.');
}

// Log a clear message at startup if the data repo or branch can't be reached.
async function checkGitHub() {
  const res = await gh('https://api.github.com/repos/' + GH_REPO + '/branches/' + encodeURIComponent(GH_BRANCH));
  if (res.ok) { console.log('GitHub storage OK: ' + GH_REPO + ' (' + GH_BRANCH + ')'); return; }
  const hint = res.status === 401 ? 'GITHUB_TOKEN is invalid or expired.'
    : res.status === 404 ? 'Repo or branch not found, or the token has no access to it. Check GITHUB_REPO is "owner/repo", the repo has a README (so ' + GH_BRANCH + ' exists), and the token is scoped to this repo.'
    : await res.text();
  console.error('GitHub storage problem (' + res.status + '): ' + hint);
}

/* ---------- passwords ---------- */

// The browser sends sha256(id:password); it is salted and hashed again here so the
// stored value cannot be replayed to sign in.
function hashPassword(clientHash, salt) {
  return crypto.scryptSync(String(clientHash), salt, 32).toString('hex');
}

function sameText(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function checkPassword(rec, clientHash) {
  if (!clientHash || !rec.passwordHash) return false;
  if (!rec.passwordSalt) return sameText(rec.passwordHash, clientHash); // older unsalted record
  return sameText(rec.passwordHash, hashPassword(clientHash, rec.passwordSalt));
}

function setPassword(rec, clientHash) {
  rec.passwordSalt = crypto.randomBytes(16).toString('hex');
  rec.passwordHash = hashPassword(clientHash, rec.passwordSalt);
}

/* ---------- HTTP ---------- */

function publicUser(rec) {
  return {
    id: rec.id,
    mobile: rec.mobile,
    name: rec.name,
    updatedAt: rec.updatedAt || null,
  };
}

function send(res, code, body) {
  const json = JSON.stringify(body);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('Request too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');

  try {
    if (url.pathname === '/api/health' && req.method === 'GET') {
      send(res, 200, { ok: true, storage: USE_GITHUB ? 'github' : 'local' });
      return;
    }

    if (url.pathname === '/api/register' && req.method === 'POST') {
      const body = await readBody(req);
      if (!validId(body.id) || !body.passwordHash || !body.mobile || !body.name) {
        send(res, 400, { error: 'Mobile, name, and password are required.' });
        return;
      }
      if (await readUser(body.id)) {
        send(res, 409, { error: 'An account with that mobile and name already exists.' });
        return;
      }
      const rec = {
        id: body.id,
        mobile: String(body.mobile || ''),
        name: String(body.name || ''),
        token: crypto.randomUUID(),
        updatedAt: new Date().toISOString(),
        progress: body.progress && typeof body.progress === 'object' ? body.progress : {},
      };
      setPassword(rec, body.passwordHash);
      await writeUser(rec, { now: true });
      send(res, 201, { ...publicUser(rec), token: rec.token, progress: rec.progress });
      return;
    }

    if (url.pathname === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      const rec = await readUser(body.id);
      if (!rec || !checkPassword(rec, body.passwordHash)) {
        send(res, 401, { error: 'Mobile, name, or password does not match a saved account.' });
        return;
      }
      // keep the existing token so other signed-in devices stay signed in
      let changed = false;
      if (!rec.token) { rec.token = crypto.randomUUID(); changed = true; }
      if (!rec.passwordSalt) { setPassword(rec, body.passwordHash); changed = true; }
      if (changed) await writeUser(rec, { now: true });
      send(res, 200, { ...publicUser(rec), token: rec.token, progress: rec.progress || {} });
      return;
    }

    const userMatch = url.pathname.match(/^\/api\/users\/([^/]+)$/);
    if (userMatch) {
      const id = decodeURIComponent(userMatch[1]);
      const rec = await readUser(id);
      if (!rec) {
        send(res, 404, { error: 'No saved account with that name.' });
        return;
      }
      if (!rec.token || !sameText(req.headers['x-token'] || '', rec.token)) {
        send(res, 401, { error: 'Sign in again to update this account.' });
        return;
      }
      if (req.method === 'GET') {
        send(res, 200, { ...publicUser(rec), progress: rec.progress || {} });
        return;
      }
      if (req.method === 'PUT') {
        const body = await readBody(req);
        const nextProgress = body.progress && typeof body.progress === 'object' ? body.progress : rec.progress;
        if (JSON.stringify(nextProgress) === JSON.stringify(rec.progress || {})) {
          send(res, 200, { ok: true, id: rec.id, unchanged: true });
          return;
        }
        rec.progress = nextProgress;
        rec.updatedAt = new Date().toISOString();
        await writeUser(rec);
        send(res, 200, { ok: true, id: rec.id, updatedAt: rec.updatedAt });
        return;
      }
    }

    // The app is a single page; nothing else in this folder is served.
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(path.join(root, 'index.html')).pipe(res);
      return;
    }

    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message || 'Server error' });
  }
});

// Write any batched progress to GitHub before the host stops the server.
async function shutdown() {
  await Promise.all([...pending.keys()].map((id) => flush(id)));
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(PORT, HOST, () => {
  console.log('DSA tracker http://127.0.0.1:' + PORT);
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) console.log('  on your network: http://' + a.address + ':' + PORT);
    }
  }
  console.log(USE_GITHUB
    ? 'Accounts save to github.com/' + GH_REPO + ' (' + GH_BRANCH + ') in ' + GH_DIR + '/'
    : 'Accounts save to ' + usersDir);
  if (USE_GITHUB) checkGitHub().catch((err) => console.error('GitHub storage check failed: ' + err.message));
});
