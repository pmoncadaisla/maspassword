// ============================================================
// Vault Internal — Registrable-domain (eTLD+1) matching
//
// Anti-phishing: saved logins are matched to the current page by
// their REGISTRABLE DOMAIN (eTLD+1), never by naive substring
// comparison. `evil-google.com`, `paypal.com.attacker.com` and
// `google.evil.com` do NOT match `google.com` / `paypal.com`.
//
// This is a pure module. It works:
//   - as an ES module (`import`) in the MV3 service worker & popup
//   - as an ES module in Node (`node --test`) for the test files
//   - defensively via `self.MP_domain` for any non-module consumer
// ============================================================

// Embedded set of common multi-part public suffixes (the part of a
// hostname that is a "registry", e.g. `co.uk`). Not exhaustive — it
// covers the required set; everything else falls back to the generic
// "last two labels" rule, which is correct for the vast majority of
// gTLDs/ccTLDs (.com, .net, .org, .io, .dev, .es, .de, ...).
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'co.jp',
  'co.kr',
  'com.au', 'net.au', 'org.au',
  'com.br',
  'com.mx',
  'co.nz',
  'co.za',
  'com.sg',
  'com.tr',
]);

// Is this hostname a bare IP literal (v4 or v6)? Web-platform
// `URL.hostname` returns IPv6 wrapped in brackets, e.g. `[::1]`.
function isIpAddress(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;      // IPv4
  if (host.startsWith('[') && host.endsWith(']')) return true; // IPv6 [..]
  if (host.includes(':')) return true;                         // bare IPv6
  return false;
}

// Reduce a hostname to its registrable domain (eTLD+1).
// Lowercases, strips a trailing dot and a single leading `www.`.
// IPs / localhost / single-label hosts are returned unchanged.
export function registrableDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return '';
  let host = hostname.trim().toLowerCase();
  host = host.replace(/\.$/, '');   // strip FQDN trailing dot
  host = host.replace(/^www\./, ''); // strip a single leading www.
  if (!host) return '';

  if (host === 'localhost') return host;
  if (isIpAddress(host)) return host;

  const labels = host.split('.');
  if (labels.length <= 2) return host;

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_PART_SUFFIXES.has(lastTwo)) {
    // The public suffix is two labels (e.g. co.uk) -> eTLD+1 is 3 labels.
    return labels.slice(-3).join('.');
  }
  // Generic case: the public suffix is one label -> eTLD+1 is 2 labels.
  return lastTwo;
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

// True iff both URLs parse AND share the same registrable domain.
// Returns false on any unparseable / empty input (fail closed).
export function domainsMatch(urlA, urlB) {
  const hostA = hostnameOf(urlA);
  const hostB = hostnameOf(urlB);
  if (!hostA || !hostB) return false;
  const regA = registrableDomain(hostA);
  const regB = registrableDomain(hostB);
  if (!regA || !regB) return false;
  return regA === regB;
}

// Defensive global exposure for non-module consumers (harmless in
// Node, where `self` is undefined).
if (typeof self !== 'undefined') {
  self.MP_domain = { registrableDomain, domainsMatch };
}
