// Session key persistence across page reloads (pull-to-refresh, Cmd+R).
//
// The unlocked AES key is kept in IndexedDB as a NON-EXTRACTABLE CryptoKey:
// after a reload it can decrypt again, but it cannot be exported — not even
// by our own code. The zero-knowledge model is unchanged (nothing ever leaves
// the device); what changes is that a reload no longer wipes the key. Lock
// and logout delete it, and the caller enforces the auto-lock deadline on
// restore via savedAt. Every function degrades silently to memory-only keys
// when IndexedDB is unavailable (private mode, storage-less browsers).

const DB_NAME = 'sesamo-keystore';
const STORE = 'session';
const RECORD = 'current';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(req && req.result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

// Persist the unlocked key for this account as a non-extractable copy.
export async function saveSessionKey(email, encKey) {
  try {
    const key = encKey.extractable
      ? await crypto.subtle.importKey(
          'raw', await crypto.subtle.exportKey('raw', encKey),
          { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      : encKey;
    const db = await openDB();
    await tx(db, 'readwrite', s => s.put({ email, key, savedAt: Date.now() }, RECORD));
    db.close();
  } catch {}
}

// → { email, key, savedAt } | null
export async function loadSessionKey() {
  try {
    const db = await openDB();
    const rec = await tx(db, 'readonly', s => s.get(RECORD));
    db.close();
    return rec || null;
  } catch {
    return null;
  }
}

// Refresh savedAt so the auto-lock deadline tracks activity, not unlock time.
export async function touchSessionKey() {
  try {
    const db = await openDB();
    const rec = await tx(db, 'readonly', s => s.get(RECORD));
    if (rec) {
      rec.savedAt = Date.now();
      await tx(db, 'readwrite', s => s.put(rec, RECORD));
    }
    db.close();
  } catch {}
}

export async function clearSessionKey() {
  try {
    const db = await openDB();
    await tx(db, 'readwrite', s => s.delete(RECORD));
    db.close();
  } catch {}
}
