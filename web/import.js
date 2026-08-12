// Import parsers for other password managers (1Password CSV + 1PIF, generic CSV).
//
// These are pure functions with no DOM or crypto dependencies so they can be unit
// tested in isolation. The caller (app.js) is responsible for encrypting the
// resulting plaintext item objects before they ever leave the device — nothing
// here touches the network. Zero-knowledge is preserved.

// RFC 4180-ish CSV parser: handles quoted fields, escaped double-quotes ("")
// inside quotes, and both LF and CRLF line endings. Returns an array of rows,
// each row an array of string fields.
export function parseCSV(text) {
  const rows = [];
  let i = 0;
  const len = text.length;

  function parseField() {
    if (i >= len || text[i] === '\n' || text[i] === '\r') return '';
    if (text[i] === '"') {
      i++; // skip opening quote
      let field = '';
      while (i < len) {
        if (text[i] === '"') {
          if (i + 1 < len && text[i + 1] === '"') {
            field += '"';
            i += 2;
          } else {
            i++; // skip closing quote
            break;
          }
        } else {
          field += text[i];
          i++;
        }
      }
      return field;
    } else {
      let field = '';
      while (i < len && text[i] !== ',' && text[i] !== '\n' && text[i] !== '\r') {
        field += text[i];
        i++;
      }
      return field;
    }
  }

  while (i < len) {
    const row = [];
    while (true) {
      row.push(parseField());
      if (i < len && text[i] === ',') {
        i++; // skip comma
      } else {
        break;
      }
    }
    // Skip line endings
    if (i < len && text[i] === '\r') i++;
    if (i < len && text[i] === '\n') i++;
    rows.push(row);
  }

  return rows;
}

export function parse1PIF(text) {
  const lines = text.split('\n');
  const entries = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('***')) continue;
    try {
      const obj = JSON.parse(trimmed);
      // Skip system entries
      if (obj.typeName === 'system.folder.Regular' || obj.typeName === 'system.folder.SavedSearch') continue;
      entries.push(obj);
    } catch {
      // Skip unparseable lines
    }
  }
  return entries;
}

export function extractTOTPSecret(otpauthUri) {
  if (!otpauthUri || !otpauthUri.startsWith('otpauth://')) return null;
  try {
    const url = new URL(otpauthUri);
    const secret = url.searchParams.get('secret');
    if (secret) return secret;
  } catch {
    // fallback regex
  }
  const match = otpauthUri.match(/[?&]secret=([A-Za-z2-7=]+)/i);
  return match ? match[1] : null;
}

// 1Password CSV without headers: OTPAuth, Notes, Password, Title, Type, URL, Username
export const OP_CSV_COLUMNS = { otpauth: 0, notes: 1, password: 2, title: 3, type: 4, url: 5, username: 6 };
export const KNOWN_HEADERS = ['title', 'username', 'password', 'url', 'website', 'notes', 'otpauth', 'type'];
// Types we skip (no useful credentials)
export const SKIP_TYPES = ['document'];

export function csvHasHeaders(firstRow) {
  const lower = firstRow.map(h => h.trim().toLowerCase());
  // If at least 2 known header names appear, treat as header row
  return lower.filter(h => KNOWN_HEADERS.includes(h)).length >= 2;
}

export function mapCSVToItems(rows) {
  if (!rows.length) return [];

  const hasHeaders = csvHasHeaders(rows[0]);

  if (hasHeaders) {
    // Header-based mapping
    if (rows.length < 2) return [];
    const headers = rows[0].map(h => h.trim().toLowerCase());
    const idx = (name) => headers.indexOf(name);
    const titleIdx = idx('title');
    if (titleIdx === -1) throw new Error('CSV missing required "Title" column');

    const usernameIdx = Math.max(idx('username'), idx('email'));
    const passwordIdx = idx('password');
    const urlIdx = Math.max(idx('website'), idx('url'));
    const notesIdx = idx('notes');
    const otpIdx = idx('otpauth');
    const typeIdx = idx('type');

    const items = [];
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      // Skip document types
      if (typeIdx >= 0 && SKIP_TYPES.includes((row[typeIdx] || '').trim().toLowerCase())) continue;
      const title = (row[titleIdx] || '').trim();
      if (!title) continue;

      const item = { title };
      if (usernameIdx >= 0 && row[usernameIdx]) item.username = row[usernameIdx].trim();
      if (passwordIdx >= 0 && row[passwordIdx]) item.password = row[passwordIdx].trim();
      if (urlIdx >= 0 && row[urlIdx]) item.url = row[urlIdx].trim();
      if (notesIdx >= 0 && row[notesIdx]) item.notes = row[notesIdx].trim();
      if (otpIdx >= 0 && row[otpIdx]) {
        const secret = extractTOTPSecret(row[otpIdx].trim());
        if (secret) item.totp_secret = secret;
      }
      items.push(item);
    }
    return items;
  }

  // Headerless 1Password CSV: OTPAuth(0), Notes(1), Password(2), Title(3), Type(4), URL(5), Username(6)
  const C = OP_CSV_COLUMNS;
  const items = [];
  for (const row of rows) {
    // Skip document types
    const type = (row[C.type] || '').trim().toLowerCase();
    if (SKIP_TYPES.includes(type)) continue;
    const title = (row[C.title] || '').trim();
    if (!title) continue;

    const item = { title };
    if (row[C.username]) item.username = row[C.username].trim();
    if (row[C.password]) item.password = row[C.password].trim();
    if (row[C.url]) item.url = row[C.url].trim();
    if (row[C.notes]) item.notes = row[C.notes].trim();
    if (row[C.otpauth]) {
      const secret = extractTOTPSecret(row[C.otpauth].trim());
      if (secret) item.totp_secret = secret;
    }
    items.push(item);
  }
  return items;
}

export function map1PIFToItems(entries) {
  const items = [];
  for (const entry of entries) {
    const title = (entry.title || '').trim();
    if (!title) continue;

    const item = { title };
    if (entry.location) item.url = entry.location;

    // Extract username/password from secureContents.fields
    const fields = entry.secureContents?.fields || [];
    for (const f of fields) {
      if (f.designation === 'username' && f.value) item.username = f.value;
      if (f.designation === 'password' && f.value) item.password = f.value;
    }

    // Extract notes
    if (entry.secureContents?.notesPlain) item.notes = entry.secureContents.notesPlain;

    // Extract TOTP from sections
    const sections = entry.secureContents?.sections || [];
    for (const section of sections) {
      for (const sf of (section.fields || [])) {
        const val = sf.v || '';
        if (typeof val === 'string' && val.startsWith('otpauth://')) {
          const secret = extractTOTPSecret(val);
          if (secret) item.totp_secret = secret;
        }
      }
    }

    items.push(item);
  }
  return items;
}

export function detectFormatAndParse(text, filename) {
  const ext = (filename || '').split('.').pop().toLowerCase();
  if (ext === '1pif') {
    const entries = parse1PIF(text);
    return map1PIFToItems(entries);
  }
  // Default to CSV
  const rows = parseCSV(text);
  return mapCSVToItems(rows);
}
