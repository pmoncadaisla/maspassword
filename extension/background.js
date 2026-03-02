// ============================================================
// Vault Internal — Chrome Extension Background Service Worker
// Handles auth, API, crypto, and item matching
// ============================================================

// --- BLAKE2b-256 (inlined) ---
const BLAKE2B_IV = [
  0xF3BCC908n, 0x6A09E667n, 0x84CAA73Bn, 0xBB67AE85n,
  0xFE94F82Bn, 0x3C6EF372n, 0x5F1D36F1n, 0xA54FF53An,
  0xADE682D1n, 0x510E527Fn, 0x2B3E6C1Fn, 0x9B05688Cn,
  0xFB41BD6Bn, 0x1F83D9ABn, 0x137E2179n, 0x5BE0CD19n,
];
const SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
];
const MASK64 = (1n << 64n) - 1n;
function LOAD64(buf, o) {
  let lo = 0n; for (let i = 7; i >= 4; i--) lo = (lo << 8n) | BigInt(buf[o+i]);
  let hi = 0n; for (let i = 3; i >= 0; i--) hi = (hi << 8n) | BigInt(buf[o+i]);
  return (lo << 32n) | hi;
}
function ADD64(a, b) { return (a + b) & MASK64; }
function ROTR64(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64; }
function bG(v, a, b, c, d, x, y) {
  v[a]=ADD64(ADD64(v[a],v[b]),x); v[d]=ROTR64(v[d]^v[a],32);
  v[c]=ADD64(v[c],v[d]); v[b]=ROTR64(v[b]^v[c],24);
  v[a]=ADD64(ADD64(v[a],v[b]),y); v[d]=ROTR64(v[d]^v[a],16);
  v[c]=ADD64(v[c],v[d]); v[b]=ROTR64(v[b]^v[c],63);
}
function bCompress(ctx, last) {
  const v = new Array(16), m = new Array(16);
  for (let i=0;i<8;i++) v[i]=ctx.h[i];
  for (let i=0;i<8;i++) v[8+i]=(BLAKE2B_IV[i*2+1]<<32n)|BLAKE2B_IV[i*2];
  v[12]^=ctx.t&MASK64; v[13]^=(ctx.t>>64n)&MASK64;
  if(last) v[14]=~v[14]&MASK64;
  for (let i=0;i<16;i++) m[i]=LOAD64(ctx.b,i*8);
  for (let i=0;i<12;i++) {
    const s=SIGMA[i];
    bG(v,0,4,8,12,m[s[0]],m[s[1]]); bG(v,1,5,9,13,m[s[2]],m[s[3]]);
    bG(v,2,6,10,14,m[s[4]],m[s[5]]); bG(v,3,7,11,15,m[s[6]],m[s[7]]);
    bG(v,0,5,10,15,m[s[8]],m[s[9]]); bG(v,1,6,11,12,m[s[10]],m[s[11]]);
    bG(v,2,7,8,13,m[s[12]],m[s[13]]); bG(v,3,4,9,14,m[s[14]],m[s[15]]);
  }
  for (let i=0;i<8;i++) ctx.h[i]=ctx.h[i]^v[i]^v[i+8];
}
function blake2bInit(outlen) {
  const ctx={h:new Array(8),b:new Uint8Array(128),c:0,t:0n,outlen};
  for (let i=0;i<8;i++) ctx.h[i]=(BLAKE2B_IV[i*2+1]<<32n)|BLAKE2B_IV[i*2];
  ctx.h[0]^=BigInt(0x01010000^outlen); return ctx;
}
function blake2bUpdate(ctx, input) {
  for (let i=0;i<input.length;i++) {
    if(ctx.c===128){ctx.t+=128n;bCompress(ctx,false);ctx.c=0;}
    ctx.b[ctx.c++]=input[i];
  }
}
function blake2bFinal(ctx) {
  ctx.t+=BigInt(ctx.c); while(ctx.c<128) ctx.b[ctx.c++]=0;
  bCompress(ctx,true);
  const out=new Uint8Array(ctx.outlen);
  for(let i=0;i<ctx.outlen;i++) out[i]=Number((ctx.h[i>>3]>>BigInt(8*(i&7)))&0xFFn);
  return out;
}
function blake2b256(data) {
  if(typeof data==='string') data=new TextEncoder().encode(data);
  const ctx=blake2bInit(32); blake2bUpdate(ctx,data); return blake2bFinal(ctx);
}
function blake2b256Multi(...inputs) {
  const ctx=blake2bInit(32);
  for(const input of inputs) {
    blake2bUpdate(ctx, typeof input==='string' ? new TextEncoder().encode(input) : input);
  }
  return blake2bFinal(ctx);
}

// --- SRP-6a (inlined) ---
const N_HEX='ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73';
const SRP_N=BigInt('0x'+N_HEX);
const SRP_g=2n;
const fieldSize=N_HEX.length/2;
function hexToBytes(h){const b=new Uint8Array(h.length/2);for(let i=0;i<h.length;i+=2)b[i/2]=parseInt(h.substr(i,2),16);return b;}
function bytesToHex(b){return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');}
function bigintToMinBytes(n){if(n===0n)return new Uint8Array([0]);let h=n.toString(16);if(h.length%2)h='0'+h;return hexToBytes(h);}
function pad(n){let h=n.toString(16);if(h.length%2)h='0'+h;while(h.length<fieldSize*2)h='00'+h;return hexToBytes(h);}
function sH(...ba){return blake2b256Multi(...ba);}
function sHBigInt(...ba){return BigInt('0x'+bytesToHex(sH(...ba)));}
function modPow(base,exp,mod){base=((base%mod)+mod)%mod;let r=1n;while(exp>0n){if(exp&1n)r=(r*base)%mod;exp>>=1n;base=(base*base)%mod;}return r;}
function randomBigInt(bits){const a=new Uint8Array(bits/8);crypto.getRandomValues(a);return BigInt('0x'+bytesToHex(a));}
function computeK(){return sHBigInt(bigintToMinBytes(SRP_N),pad(SRP_g));}

function srpLogin(email, password) {
  const ih=blake2b256(email), ph=blake2b256(password);
  const a=randomBigInt(fieldSize*8);
  const A=modPow(SRP_g,a,SRP_N);
  const k=computeK();
  const credentials=bytesToHex(ih)+':'+bytesToHex(bigintToMinBytes(A));
  return {
    credentials,
    generate(serverCreds) {
      const parts=serverCreds.split(':');
      const salt=hexToBytes(parts[0]);
      const B=BigInt('0x'+parts[1]);
      if(B%SRP_N===0n) throw new Error('Invalid B');
      const u=sHBigInt(pad(A),pad(B));
      if(u===0n) throw new Error('Invalid u');
      const x=sHBigInt(ih,ph,salt);
      const gx=modPow(SRP_g,x,SRP_N);
      let t1=(B-k*gx)%SRP_N; if(t1<0n)t1+=SRP_N;
      const S=modPow(t1,a+u*x,SRP_N);
      const K=sH(bigintToMinBytes(S));
      const M=sH(K,bigintToMinBytes(A),bigintToMinBytes(B),ih,salt,bigintToMinBytes(SRP_N),bigintToMinBytes(SRP_g));
      return {proof:bytesToHex(M), K, M, verify(sp){return bytesToHex(sH(K,M))===sp;}};
    }
  };
}

// --- Crypto helpers ---
async function deriveKey(password, email) {
  const enc=new TextEncoder();
  const km=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:enc.encode('vault-internal:'+email),iterations:600000,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},true,['encrypt','decrypt'] // extractable for session storage
  );
}
async function encryptData(key, plaintext) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(plaintext));
  const c=new Uint8Array(iv.length+ct.byteLength);c.set(iv);c.set(new Uint8Array(ct),iv.length);
  return btoa(String.fromCharCode(...c));
}
async function decryptData(key, encoded) {
  const c=Uint8Array.from(atob(encoded),x=>x.charCodeAt(0));
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:c.slice(0,12)},key,c.slice(12));
  return new TextDecoder().decode(pt);
}
function generatePassword(length=20) {
  const chars='abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
  const a=new Uint8Array(length);crypto.getRandomValues(a);
  return Array.from(a,b=>chars[b%chars.length]).join('');
}
async function exportKey(key) {
  const raw=await crypto.subtle.exportKey('raw',key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}
async function importKey(b64) {
  const raw=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
  return crypto.subtle.importKey('raw',raw,{name:'AES-GCM',length:256},true,['encrypt','decrypt']);
}

// --- RSA helpers for shared vaults ---
async function decryptPrivateKey(encKey, encrypted) {
  const json = await decryptData(encKey, encrypted);
  const jwk = JSON.parse(json);
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

async function decryptWithPrivateKey(privKey, encoded) {
  const ciphertext = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const plaintext = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}

async function importVaultKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

async function exportRsaKey(rsaKey) {
  const jwk = await crypto.subtle.exportKey('jwk', rsaKey);
  return JSON.stringify(jwk);
}

async function importRsaKey(jwkStr) {
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

// --- State ---
let serverUrl = '';
let token = null;
let encKey = null;
let privateKey = null; // RSA private key for shared vault decryption
let vaultsCache = [];
let vaultKeyCache = {}; // vaultId -> CryptoKey
let allItemsCache = []; // [{vaultId, itemId, data: {title,username,password,url,...}}]

// --- Persistence (chrome.storage.session) ---
async function saveSession() {
  const data = { token };
  if (encKey) data.encKeyB64 = await exportKey(encKey);
  if (privateKey) data.privateKeyJwk = await exportRsaKey(privateKey);
  await chrome.storage.session.set(data);
}

async function restoreSession() {
  const { serverUrl: url } = await chrome.storage.local.get('serverUrl');
  if (url) serverUrl = url;
  const { token: t, encKeyB64, privateKeyJwk } = await chrome.storage.session.get(['token', 'encKeyB64', 'privateKeyJwk']);
  if (t) token = t;
  if (encKeyB64) encKey = await importKey(encKeyB64);
  if (privateKeyJwk) privateKey = await importRsaKey(privateKeyJwk);
}

// --- Vault decryption key helper (handles both private and shared vaults) ---
async function getVaultDecryptionKey(vault) {
  if (!vault.team_id) {
    // Private vault: use encKey derived from master password
    return encKey;
  }
  // Shared vault: get vault key via API, decrypt with RSA private key
  if (vaultKeyCache[vault.id]) {
    return vaultKeyCache[vault.id];
  }
  if (!privateKey) return null;
  const resp = await api('GET', `/api/vaults/${vault.id}/key`);
  const vaultKeyBase64 = await decryptWithPrivateKey(privateKey, resp.encrypted_vault_key);
  const vaultCryptoKey = await importVaultKey(vaultKeyBase64);
  vaultKeyCache[vault.id] = vaultCryptoKey;
  return vaultCryptoKey;
}

// --- API ---
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(serverUrl + path, opts);
  const data = res.status !== 204 ? await res.json().catch(() => null) : null;
  if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
  return data;
}

// --- Auth ---
async function login(email, password) {
  const client = srpLogin(email, password);
  const step1 = await api('POST', '/auth/login/step1', { email, client_public: client.credentials });
  const result = client.generate(step1.server_public);
  const step2 = await api('POST', '/auth/login/step2', { session_id: step1.session_id, client_proof: result.proof });
  if (!result.verify(step2.server_proof)) throw new Error('Server verification failed');
  token = step2.token;
  encKey = await deriveKey(password, email);

  // Decrypt RSA private key for shared vault access
  if (step2.encrypted_private_key) {
    privateKey = await decryptPrivateKey(encKey, step2.encrypted_private_key);
  }

  vaultKeyCache = {};
  await saveSession();
  await refreshAllItems();
  return { ok: true };
}

function logout() {
  token = null;
  encKey = null;
  privateKey = null;
  vaultsCache = [];
  vaultKeyCache = {};
  allItemsCache = [];
  chrome.storage.session.clear();
}

function isLoggedIn() {
  return !!token && !!encKey;
}

// --- Items cache ---
async function refreshAllItems() {
  if (!isLoggedIn()) return;
  vaultsCache = (await api('GET', '/api/vaults')) || [];
  allItemsCache = [];
  for (const vault of vaultsCache) {
    let key;
    try {
      key = await getVaultDecryptionKey(vault);
    } catch {
      continue; // skip vaults we can't decrypt (e.g. missing private key)
    }
    if (!key) continue;

    const items = (await api('GET', `/api/vaults/${vault.id}/items`)) || [];
    for (const item of items) {
      try {
        const json = await decryptData(key, item.data_encrypted);
        const data = JSON.parse(json);
        allItemsCache.push({
          vaultId: vault.id,
          itemId: item.id,
          version: item.version,
          data,
        });
      } catch {}
    }
  }
}

// --- URL matching ---
function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch { return ''; }
}

function matchItems(url) {
  const domain = extractDomain(url);
  if (!domain) return [];
  return allItemsCache.filter(item => {
    const itemDomain = extractDomain(item.data.url || '');
    if (itemDomain && domain.includes(itemDomain)) return true;
    if (itemDomain && itemDomain.includes(domain)) return true;
    // Also check title as fallback
    const title = (item.data.title || '').toLowerCase();
    const domainParts = domain.split('.');
    return domainParts.some(part => part.length > 2 && title.includes(part));
  });
}

// --- Save new item ---
async function saveNewItem(vaultId, data) {
  if (!isLoggedIn()) throw new Error('Not logged in');
  const vault = vaultsCache.find(v => v.id === vaultId);
  if (!vault) throw new Error('Vault not found');
  const key = await getVaultDecryptionKey(vault);
  if (!key) throw new Error('Cannot decrypt vault key');
  const json = JSON.stringify(data);
  const dataEnc = await encryptData(key, json);
  const newItem = await api('POST', `/api/vaults/${vaultId}/items`, { data_encrypted: dataEnc });
  // Add to cache
  allItemsCache.push({ vaultId, itemId: newItem?.id, version: newItem?.version, data });
  return newItem;
}

// --- Message handler ---
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(e => sendResponse({ error: e.message }));
  return true; // async response
});

async function handleMessage(msg) {
  await restoreSession();

  switch (msg.type) {
    case 'login':
      return login(msg.email, msg.password);

    case 'logout':
      logout();
      return { ok: true };

    case 'getStatus':
      return { loggedIn: isLoggedIn(), serverUrl };

    case 'setServerUrl':
      serverUrl = msg.url.replace(/\/+$/, '');
      await chrome.storage.local.set({ serverUrl });
      return { ok: true };

    case 'getMatchingItems':
      return { items: matchItems(msg.url) };

    case 'getAllItems':
      return { items: allItemsCache };

    case 'getVaults':
      return { vaults: vaultsCache };

    case 'refreshItems':
      await refreshAllItems();
      return { ok: true, count: allItemsCache.length };

    case 'saveItem':
      return saveNewItem(msg.vaultId, msg.data);

    case 'generatePassword':
      return { password: generatePassword(msg.length || 20) };

    case 'fillCredentials':
      // Send to content script of the active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, {
          type: 'fill',
          username: msg.username,
          password: msg.password,
        });
      }
      return { ok: true };

    default:
      return { error: 'Unknown message type' };
  }
}

// Restore session on startup
restoreSession();
