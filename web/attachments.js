// attachments.js — helpers for file attachments stored INSIDE the encrypted
// item blob as base64.
//
// Zero-knowledge invariant: this module never encrypts and never uploads.
// It only converts File/Blob -> {name, type, size, data(base64)} objects that
// the caller embeds in the item's data object BEFORE encryption, so raw file
// bytes never leave the device unencrypted.

export const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024; // 2 MB per file
export const MAX_ATTACHMENTS = 5; // per item

// Base64-encode raw bytes without exceeding argument limits (chunked).
function bytesToBase64(bytes) {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/**
 * Convert a File (or Blob with .name) into an attachment record:
 *   { name, type, size, data }   — data is base64 WITHOUT any 'data:' prefix.
 *
 * Rejects with Error('too-big') when file.size > MAX_ATTACHMENT_BYTES.
 * Uses FileReader when available (browsers); falls back to blob.arrayBuffer()
 * so it also works in Node tests.
 */
export function fileToAttachment(file) {
  return new Promise((resolve, reject) => {
    if (!file || typeof file.size !== 'number') {
      reject(new Error('not-a-file'));
      return;
    }
    if (file.size > MAX_ATTACHMENT_BYTES) {
      reject(new Error('too-big'));
      return;
    }

    const done = (base64) => resolve({
      name: file.name || 'file',
      type: file.type || '',
      size: file.size,
      data: base64,
    });

    if (typeof FileReader !== 'undefined') {
      const reader = new FileReader();
      reader.onerror = () => reject(reader.error || new Error('read-failed'));
      reader.onload = () => {
        // reader.result is 'data:<type>;base64,<data>' — keep only the payload.
        const url = String(reader.result || '');
        const comma = url.indexOf(',');
        done(comma >= 0 ? url.slice(comma + 1) : '');
      };
      reader.readAsDataURL(file);
    } else if (typeof file.arrayBuffer === 'function') {
      file.arrayBuffer()
        .then((buf) => done(bytesToBase64(new Uint8Array(buf))))
        .catch(reject);
    } else {
      reject(new Error('unsupported-file'));
    }
  });
}

/**
 * Data URL for previewing/downloading a stored attachment.
 */
export function attachmentDataUrl(att) {
  const type = (att && att.type) || 'application/octet-stream';
  const data = (att && att.data) || '';
  return `data:${type};base64,${data}`;
}

/**
 * Human-readable size: '12 B', '532 KB', '1.4 MB', '3.2 GB'.
 * One decimal below 10 in the unit, integers otherwise.
 */
export function formatSize(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n;
  let i = -1;
  do {
    value /= 1024;
    i++;
  } while (value >= 1024 && i < units.length - 1);
  const shown = value < 10 ? Math.round(value * 10) / 10 : Math.round(value);
  return `${shown} ${units[i]}`;
}
