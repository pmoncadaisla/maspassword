import test from 'node:test';
import assert from 'node:assert/strict';
import { registrableDomain, domainsMatch } from './domain.js';

test('registrableDomain: strips www and generic gTLD', () => {
  assert.equal(registrableDomain('www.google.com'), 'google.com');
});

test('registrableDomain: reduces subdomains to eTLD+1', () => {
  assert.equal(registrableDomain('accounts.google.com'), 'google.com');
});

test('registrableDomain: multi-part suffix co.uk', () => {
  assert.equal(registrableDomain('foo.bar.co.uk'), 'bar.co.uk');
});

test('registrableDomain: multi-part suffix com.au', () => {
  assert.equal(registrableDomain('a.b.com.au'), 'b.com.au');
});

test('registrableDomain: localhost is returned as-is', () => {
  assert.equal(registrableDomain('localhost'), 'localhost');
});

test('registrableDomain: extra coverage', () => {
  assert.equal(registrableDomain('GOOGLE.COM'), 'google.com'); // lowercased
  assert.equal(registrableDomain('google.com.'), 'google.com'); // trailing dot
  assert.equal(registrableDomain('login.example.co.jp'), 'example.co.jp');
  assert.equal(registrableDomain('127.0.0.1'), '127.0.0.1'); // IPv4 as-is
  assert.equal(registrableDomain(''), '');
});

test('domainsMatch: TRUE for same registrable domain', () => {
  assert.equal(
    domainsMatch('https://accounts.google.com/login', 'https://google.com'),
    true
  );
  assert.equal(
    domainsMatch('https://www.paypal.com', 'https://paypal.com/signin'),
    true
  );
});

// --- Anti-phishing: these MUST be false ---
test('domainsMatch: FALSE for evil-google.com vs google.com', () => {
  assert.equal(domainsMatch('https://evil-google.com', 'https://google.com'), false);
});

test('domainsMatch: FALSE for paypal.com.attacker.com vs paypal.com', () => {
  assert.equal(
    domainsMatch('https://paypal.com.attacker.com', 'https://paypal.com'),
    false
  );
});

test('domainsMatch: FALSE for google.evil.com vs google.com', () => {
  assert.equal(domainsMatch('https://google.evil.com', 'https://google.com'), false);
});

test('domainsMatch: FALSE for empty / invalid url vs anything', () => {
  assert.equal(domainsMatch('', 'https://google.com'), false);
  assert.equal(domainsMatch('not a url', 'https://google.com'), false);
  assert.equal(domainsMatch('https://google.com', ''), false);
  assert.equal(domainsMatch(null, 'https://google.com'), false);
});
