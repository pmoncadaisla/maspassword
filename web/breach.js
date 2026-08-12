// HaveIBeenPwned breach check using the k-anonymity range API.
//
// Privacy property (k-anonymity):
//   We SHA-1 the password locally, then send ONLY the first 5 hex characters of
//   that hash to the API. The server responds with every hash suffix (and its
//   breach count) that shares those 5 prefix characters — typically several
//   hundred candidates. We match the remaining 35 characters locally. Because
//   the full hash and the plaintext password never leave the device, the server
//   cannot learn which password was checked: it only ever sees a 5-char prefix
//   shared by many thousands of distinct passwords.
//
// Pure ES module, no external deps. Works in the browser and under Node 22.

// SHA-1 hash of a string, returned as an UPPERCASE hex string (40 chars).
export async function sha1Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

// Return how many times `password` appears in the HaveIBeenPwned corpus.
// Uses k-anonymity: only the 5-char SHA-1 prefix is ever sent over the network.
// `fetchImpl` may be injected (e.g. for tests); defaults to globalThis.fetch.
export async function checkPwnedCount(password, { fetchImpl } = {}) {
  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== 'function') {
    throw new Error('No fetch implementation available');
  }

  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);   // sent to the server
  const suffix = hash.slice(5);      // 35 chars, matched locally only

  const response = await doFetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const body = await response.text();

  for (const line of body.split(/\r?\n/)) {
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const lineSuffix = line.slice(0, sep).trim();
    if (lineSuffix.toUpperCase() === suffix.toUpperCase()) {
      const count = parseInt(line.slice(sep + 1).trim(), 10);
      return Number.isNaN(count) ? 0 : count;
    }
  }

  return 0;
}
