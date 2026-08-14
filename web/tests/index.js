// Test aggregator.
//
// This Node build's `node --test <dir>` does NOT recursively discover test
// files in a directory positional argument — it resolves the directory as a
// module. Providing this index.js lets the exact command from the definition
// of done, `node --test web/tests/`, resolve here and register every test.
//
// It is intentionally NOT named `*.test.js`, so the glob form
// `node --test web/tests/*.test.js` and no-arg discovery never double-run it.
import './generator.test.js';
import './strength.test.js';
import './breach.test.js';
import './onboarding.test.js';
