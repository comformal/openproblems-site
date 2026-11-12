// Serves the encrypted site. With a key stored by the gate page, requests
// inside the worker's scope are answered with decrypted files from vault/;
// navigations to unknown paths get the app's index.html (client-side routes).
// Without a valid key, requests fall through to the network (the gate page).
const scope = new URL(self.registration.scope);
const store = { db: 'openproblems-vault', table: 'keys', name: 'site' };
let session = null;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('message', (event) => {
  if (event.data === 'reset') session = null;
  if (event.data === 'lock') event.waitUntil(lock());
});

function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(store.db, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(store.table);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function keyStore(mode, action) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const request = action(db.transaction(store.table, mode).objectStore(store.table));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function lock() {
  session = null;
  await keyStore('readwrite', (table) => table.delete(store.name));
}

async function decrypt(key, id) {
  const response = await fetch(new URL(`vault/${id}.bin`, scope));
  if (!response.ok) throw new Error(`Missing vault/${id}.bin`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));
}

// Revalidate the file index on navigations so a new deploy is picked up.
async function open(refresh) {
  if (session && !refresh) return session;
  const key = await keyStore('readonly', (table) => table.get(store.name)).catch(() => undefined);
  if (!key) return (session = null);
  const params = await fetch(new URL('vault/params.json', scope), { cache: 'no-cache' }).then((r) => r.json());
  if (session?.index === params.index) return session;
  try {
    const { files } = JSON.parse(new TextDecoder().decode(await decrypt(key, params.index)));
    return (session = { key, files, index: params.index });
  } catch {
    await lock(); // Password changed or index unreadable: back to the gate.
    return null;
  }
}

async function respond(request, rel) {
  const navigation = request.mode === 'navigate';
  for (const refresh of [navigation, true]) {
    const current = await open(refresh).catch(() => null);
    if (!current) return fetch(request);
    const entry = current.files[rel] || current.files[rel + 'index.html']
      || (navigation ? current.files['index.html'] : undefined);
    if (!entry) return fetch(request);
    try {
      return new Response(await decrypt(current.key, entry.id), { headers: { 'Content-Type': entry.type } });
    } catch {
      if (refresh) break; // Stale index after a deploy: retry once with a fresh one.
    }
  }
  return fetch(request);
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname) || event.request.method !== 'GET') return;
  let rel;
  try { rel = decodeURIComponent(url.pathname.slice(scope.pathname.length)); } catch { return; }
  if (rel === 'sw.js' || rel.startsWith('vault/')) return;
  if (url.searchParams.has('lock')) {
    event.respondWith(lock().then(() => fetch(new URL('index.html', scope))));
    return;
  }
  event.respondWith(respond(event.request, rel));
});
