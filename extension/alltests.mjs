// Test aggregator.
//
// Node's test runner in some v22.x releases does not expand a bare
// directory argument (`node --test extension/`): instead it resolves
// the directory as an entry module. package.json `main` points here so
// that invocation still runs the whole suite. This file just imports
// the real test files (whose top-level `test()` calls self-register).
//
// Normal invocations — `cd extension && node --test`, or
// `node --test extension/*.test.mjs` — discover the `*.test.mjs`
// files directly and ignore this aggregator (its name matches no test
// glob), so tests are never double-counted.
import './domain.test.mjs';
import './totp.test.mjs';
import './webauthn.test.mjs';
