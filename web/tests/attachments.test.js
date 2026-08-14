import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_ATTACHMENT_BYTES,
  MAX_ATTACHMENTS,
  fileToAttachment,
  attachmentDataUrl,
  formatSize,
} from '../attachments.js';

test('limit constants match the spec (2 MB, 5 files)', () => {
  assert.equal(MAX_ATTACHMENT_BYTES, 2 * 1024 * 1024);
  assert.equal(MAX_ATTACHMENTS, 5);
});

test('fileToAttachment converts a file to base64 (no data: prefix) and keeps metadata', async () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const file = new File([bytes], 'blob.bin', { type: 'application/octet-stream' });

  const att = await fileToAttachment(file);
  assert.equal(att.name, 'blob.bin');
  assert.equal(att.type, 'application/octet-stream');
  assert.equal(att.size, 256);
  assert.ok(!att.data.startsWith('data:'), 'data must not carry a data: prefix');
  assert.match(att.data, /^[A-Za-z0-9+/]+=*$/, 'data must be plain base64');

  const decoded = Uint8Array.from(atob(att.data), (c) => c.charCodeAt(0));
  assert.deepEqual(decoded, bytes, 'base64 roundtrips the exact bytes');
});

test('fileToAttachment handles text files and empty type', async () => {
  const file = new File(['hola señor'], 'saludo.txt', { type: 'text/plain' });
  const att = await fileToAttachment(file);
  assert.equal(att.type, 'text/plain');
  const decoded = new TextDecoder().decode(
    Uint8Array.from(atob(att.data), (c) => c.charCodeAt(0)),
  );
  assert.equal(decoded, 'hola señor');

  const untyped = await fileToAttachment(new File(['x'], 'x.bin'));
  assert.equal(untyped.type, '');
});

test("fileToAttachment rejects with Error('too-big') above the 2 MB limit", async () => {
  const big = new File([new Uint8Array(MAX_ATTACHMENT_BYTES + 1)], 'big.bin');
  await assert.rejects(fileToAttachment(big), { message: 'too-big' });
});

test('fileToAttachment accepts a file of exactly MAX_ATTACHMENT_BYTES', async () => {
  const edge = new File([new Uint8Array(MAX_ATTACHMENT_BYTES)], 'edge.bin');
  const att = await fileToAttachment(edge);
  assert.equal(att.size, MAX_ATTACHMENT_BYTES);
  assert.ok(att.data.length > 0);
});

test('fileToAttachment rejects non-file input', async () => {
  await assert.rejects(fileToAttachment(null));
  await assert.rejects(fileToAttachment({}));
});

test('attachmentDataUrl builds a data: URL and defaults the MIME type', () => {
  assert.equal(
    attachmentDataUrl({ type: 'image/png', data: 'AAAA' }),
    'data:image/png;base64,AAAA',
  );
  assert.equal(
    attachmentDataUrl({ data: 'AAAA' }),
    'data:application/octet-stream;base64,AAAA',
  );
});

test('formatSize formats bytes, KB, MB and GB like the spec examples', () => {
  assert.equal(formatSize(12), '12 B');
  assert.equal(formatSize(0), '0 B');
  assert.equal(formatSize(1023), '1023 B');
  assert.equal(formatSize(1024), '1 KB');
  assert.equal(formatSize(1536), '1.5 KB');
  assert.equal(formatSize(532 * 1024), '532 KB');
  assert.equal(formatSize(Math.round(1.4 * 1024 * 1024)), '1.4 MB');
  assert.equal(formatSize(2 * 1024 * 1024), '2 MB');
  assert.equal(formatSize(Math.round(3.2 * 1024 * 1024 * 1024)), '3.2 GB');
});
