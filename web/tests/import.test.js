import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseCSV,
  parse1PIF,
  extractTOTPSecret,
  csvHasHeaders,
  mapCSVToItems,
  map1PIFToItems,
  detectFormatAndParse,
} from '../import.js';

// --- parseCSV ---------------------------------------------------------------

test('parseCSV: simple unquoted row', () => {
  assert.deepEqual(parseCSV('a,b,c'), [['a', 'b', 'c']]);
});

test('parseCSV: quoted field containing a comma', () => {
  assert.deepEqual(parseCSV('"a,b",c'), [['a,b', 'c']]);
});

test('parseCSV: escaped double-quote inside a quoted field', () => {
  assert.deepEqual(parseCSV('"say ""hi""",x'), [['say "hi"', 'x']]);
});

test('parseCSV: CRLF line endings', () => {
  assert.deepEqual(parseCSV('a,b\r\nc,d'), [['a', 'b'], ['c', 'd']]);
});

test('parseCSV: trailing newline does not add an empty row', () => {
  assert.deepEqual(parseCSV('a,b\n'), [['a', 'b']]);
});

test('parseCSV: empty fields are preserved', () => {
  assert.deepEqual(parseCSV('a,,c'), [['a', '', 'c']]);
});

test('parseCSV: newline inside a quoted field is kept', () => {
  assert.deepEqual(parseCSV('"line1\nline2",b'), [['line1\nline2', 'b']]);
});

test('parseCSV: empty input yields no rows', () => {
  assert.deepEqual(parseCSV(''), []);
});

// --- extractTOTPSecret ------------------------------------------------------

test('extractTOTPSecret: reads secret from a well-formed otpauth URI', () => {
  assert.equal(
    extractTOTPSecret('otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme'),
    'JBSWY3DPEHPK3PXP'
  );
});

test('extractTOTPSecret: non-otpauth string returns null', () => {
  assert.equal(extractTOTPSecret('https://example.com'), null);
  assert.equal(extractTOTPSecret(''), null);
  assert.equal(extractTOTPSecret(null), null);
});

test('extractTOTPSecret: otpauth without a secret returns null', () => {
  assert.equal(extractTOTPSecret('otpauth://totp/Acme:bob?issuer=Acme'), null);
});

// --- csvHasHeaders ----------------------------------------------------------

test('csvHasHeaders: true when >=2 known header names present', () => {
  assert.equal(csvHasHeaders(['Title', 'Username', 'Password']), true);
  assert.equal(csvHasHeaders(['otpauth', 'notes', 'password', 'title']), true);
});

test('csvHasHeaders: false for a plain data row', () => {
  assert.equal(csvHasHeaders(['My Login', 'bob@example.com', 'hunter2']), false);
});

// --- mapCSVToItems (header mode) --------------------------------------------

test('mapCSVToItems: header-based mapping of core fields', () => {
  const rows = parseCSV('Title,Username,Password,URL\nGitHub,bob,s3cret,https://github.com');
  assert.deepEqual(mapCSVToItems(rows), [
    { title: 'GitHub', username: 'bob', password: 's3cret', url: 'https://github.com' },
  ]);
});

test('mapCSVToItems: email column is used as username fallback', () => {
  const rows = parseCSV('Title,Email,Password\nSite,bob@example.com,pw');
  assert.deepEqual(mapCSVToItems(rows), [
    { title: 'Site', username: 'bob@example.com', password: 'pw' },
  ]);
});

test('mapCSVToItems: website column is used as url fallback', () => {
  const rows = parseCSV('Title,Website,Password\nSite,https://a.test,pw');
  assert.equal(mapCSVToItems(rows)[0].url, 'https://a.test');
});

test('mapCSVToItems: rows without a title are skipped', () => {
  const rows = parseCSV('Title,Password\n,orphan\nReal,pw');
  const items = mapCSVToItems(rows);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'Real');
});

test('mapCSVToItems: document type rows are skipped', () => {
  const rows = parseCSV('Title,Type,Password\nMyDoc,Document,x\nMyLogin,Login,pw');
  const items = mapCSVToItems(rows);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'MyLogin');
});

test('mapCSVToItems: otpauth column is converted to totp_secret', () => {
  const rows = parseCSV(
    'Title,OTPAuth\nSite,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP'
  );
  assert.equal(mapCSVToItems(rows)[0].totp_secret, 'JBSWY3DPEHPK3PXP');
});

test('mapCSVToItems: missing Title column throws', () => {
  const rows = parseCSV('Username,Password\nbob,pw');
  assert.throws(() => mapCSVToItems(rows), /Title/);
});

test('mapCSVToItems: empty input yields no items', () => {
  assert.deepEqual(mapCSVToItems([]), []);
});

// --- mapCSVToItems (headerless 1Password order) -----------------------------

test('mapCSVToItems: headerless 1Password column order', () => {
  // OTPAuth, Notes, Password, Title, Type, URL, Username
  const rows = parseCSV(
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,my note,pw123,My Bank,Login,https://bank.test,bob'
  );
  assert.deepEqual(mapCSVToItems(rows), [
    {
      title: 'My Bank',
      username: 'bob',
      password: 'pw123',
      url: 'https://bank.test',
      notes: 'my note',
      totp_secret: 'JBSWY3DPEHPK3PXP',
    },
  ]);
});

// --- map1PIFToItems ---------------------------------------------------------

test('map1PIFToItems: extracts fields, notes, url and TOTP', () => {
  const entries = [
    {
      title: 'Example',
      location: 'https://example.com',
      secureContents: {
        fields: [
          { designation: 'username', value: 'alice' },
          { designation: 'password', value: 'topsecret' },
        ],
        notesPlain: 'hello notes',
        sections: [
          { fields: [{ v: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' }] },
        ],
      },
    },
  ];
  assert.deepEqual(map1PIFToItems(entries), [
    {
      title: 'Example',
      url: 'https://example.com',
      username: 'alice',
      password: 'topsecret',
      notes: 'hello notes',
      totp_secret: 'JBSWY3DPEHPK3PXP',
    },
  ]);
});

test('map1PIFToItems: entries without a title are skipped', () => {
  assert.deepEqual(map1PIFToItems([{ secureContents: { fields: [] } }]), []);
});

test('parse1PIF: skips markers and system folders, parses JSON lines', () => {
  const text = [
    '***5642bee8-a5ff-11dc-8314-0800200c9a66***',
    JSON.stringify({ typeName: 'system.folder.Regular', title: 'Folder' }),
    JSON.stringify({ title: 'Real Login', secureContents: { fields: [] } }),
    'not json at all',
  ].join('\n');
  const entries = parse1PIF(text);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].title, 'Real Login');
});

// --- detectFormatAndParse ---------------------------------------------------

test('detectFormatAndParse: .1pif extension routes to the 1PIF parser', () => {
  const text = JSON.stringify({
    title: 'PIF Item',
    secureContents: { fields: [{ designation: 'username', value: 'u' }] },
  });
  const items = detectFormatAndParse(text, 'export.1pif');
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'PIF Item');
  assert.equal(items[0].username, 'u');
});

test('detectFormatAndParse: .csv extension routes to the CSV parser', () => {
  const items = detectFormatAndParse('Title,Password\nSite,pw', 'export.csv');
  assert.deepEqual(items, [{ title: 'Site', password: 'pw' }]);
});

test('detectFormatAndParse: extension match is case-insensitive', () => {
  const text = JSON.stringify({ title: 'X', secureContents: { fields: [] } });
  assert.equal(detectFormatAndParse(text, 'EXPORT.1PIF').length, 1);
});
