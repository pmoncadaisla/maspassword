// Dependency-free "zxcvbn-lite" password strength estimator.
// Pure module: no DOM, no window, no network, no globals beyond Math/String/RegExp.
// Deterministic — the same input always yields the same output.

// Small embedded blacklist of the most common passwords (lowercased). A real
// deployment would use a much larger list; this is enough to flag the worst
// offenders offline.
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', '12345678', '12345', '1234567', 'qwerty',
  'abc123', 'password1', 'password123', '111111', '123123', 'admin', 'letmein',
  'welcome', 'monkey', '1234567890', 'iloveyou', 'dragon', 'sunshine', 'princess',
  'football', '000000', '654321', 'superman', 'qazwsx', 'michael', 'shadow',
  'master', 'jennifer', 'jordan', 'hunter', 'harley', 'ranger', 'buster', 'thomas',
  'tigger', 'robert', 'soccer', 'batman', 'test', 'pass', 'killer', 'hockey',
  'george', 'charlie', 'andrew', 'michelle', 'love', 'jesus', 'ninja', 'mustang',
  '1q2w3e4r', '1qaz2wsx', 'qwertyuiop', '121212', '555555', '666666', '777777',
  '888888', '999999', '112233', '131313', '232323', 'aaaaaa', 'abcabc', 'abcdef',
  'access', 'adobe123', 'ashley', 'azerty', 'bailey', 'baseball', 'chelsea',
  'computer', 'daniel', 'freedom', 'ginger', 'gizmo', 'hannah', 'iloveu',
  'internet', 'jackson', 'jasmine', 'joshua', 'junior', 'letmein1', 'liverpool',
  'london', 'matrix', 'matthew', 'maverick', 'maggie', 'monkey1', 'mother',
  'nascar', 'nicole', 'oliver', 'orange', 'pepper', 'purple', 'qwe123', 'qwerty1',
  'qwerty123', 'rangers', 'samantha', 'samsung', 'secret', 'silver', 'snoopy',
  'spider', 'startrek', 'summer', 'taylor', 'tennis', 'testing', 'trustno1',
  'tucker', 'whatever', 'william', 'willie', 'winter', 'yankees', 'zxcvbnm',
  '123qwe', '147258', '159753', '1qazxsw2', '7777777', 'aa123456', 'admin123',
  'changeme', 'cheese', 'coffee', 'cookie', 'hello', 'hello123', 'letmein123',
  'login', 'passw0rd', 'qwerty12', 'root', 'temp', 'user', 'welcome1',
  'welcome123', 'zaq12wsx', 'football1', 'baseball1', 'starwars',
]);

// Rows/lines used to detect sequential runs like "abc", "123", "qwerty".
const SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz',
  '01234567890',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
];

// Size of the character pool implied by the classes the password uses.
function poolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pool;
}

// True if the password contains a run of >= 3 consecutive characters from any
// known sequence (forward or reversed), case-insensitive.
function hasSequentialRun(pw) {
  const lower = pw.toLowerCase();
  for (const seq of SEQUENCES) {
    for (let i = 0; i + 3 <= seq.length; i++) {
      const chunk = seq.slice(i, i + 3);
      const rev = chunk.split('').reverse().join('');
      if (lower.includes(chunk) || lower.includes(rev)) return true;
    }
  }
  return false;
}

// True if the password contains a character repeated 3+ times (aaa) or a
// repeated block (abcabc).
function hasRepeats(pw) {
  if (/(.)\1{2,}/.test(pw)) return true;
  if (/(.{2,})\1+/.test(pw)) return true;
  return false;
}

// Turn a duration in seconds into a short human string like "3 hours".
function humanTime(seconds) {
  if (!isFinite(seconds) || seconds >= 3.15e11) return 'centuries';
  if (seconds < 1) return 'less than a second';
  const units = [
    ['century', 60 * 60 * 24 * 365 * 100],
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1],
  ];
  for (const [name, secs] of units) {
    if (seconds >= secs) {
      const n = Math.floor(seconds / secs);
      return `${n} ${name}${n === 1 ? '' : 's'}`;
    }
  }
  return 'less than a second';
}

// Estimate password strength. Returns:
//   { score, entropyBits, crackTimeSeconds, crackTimeDisplay, label,
//     warnings, suggestions }
export function estimateStrength(password) {
  const pw = typeof password === 'string' ? password : '';
  const warnings = [];
  const suggestions = [];

  const pool = poolSize(pw);
  let entropyBits = pool > 0 ? pw.length * Math.log2(pool) : 0;

  // --- Penalties ---------------------------------------------------------
  if (pw.length > 0 && pw.length < 8) {
    entropyBits *= 0.5;
    warnings.push('Password is too short.');
    suggestions.push('Use at least 12 characters.');
  }

  if (pw.length > 0 && /^[a-z]+$/.test(pw)) {
    entropyBits *= 0.75;
    warnings.push('Only lowercase letters.');
    suggestions.push('Add uppercase letters, numbers, and symbols.');
  }

  if (pw.length > 0 && /^[0-9]+$/.test(pw)) {
    entropyBits *= 0.5;
    warnings.push('Only digits.');
    suggestions.push('Avoid using only numbers.');
  }

  if (hasSequentialRun(pw)) {
    entropyBits *= 0.6;
    warnings.push('Contains a sequential run (like "abc", "123", or "qwerty").');
    suggestions.push('Avoid predictable sequences.');
  }

  if (hasRepeats(pw)) {
    entropyBits *= 0.6;
    warnings.push('Contains repeated characters or patterns.');
    suggestions.push('Avoid repeated characters or repeated blocks.');
  }

  if (COMMON_PASSWORDS.has(pw.toLowerCase())) {
    // Force it into the "very weak" bucket regardless of composition.
    entropyBits = Math.min(entropyBits, 8);
    warnings.push('This is a commonly used password.');
    suggestions.push('Choose a password that is not on common-password lists.');
  }

  if (entropyBits < 0) entropyBits = 0;

  // --- Score bucket from final entropy -----------------------------------
  let score;
  if (entropyBits < 28) score = 0;
  else if (entropyBits < 36) score = 1;
  else if (entropyBits < 60) score = 2;
  else if (entropyBits < 128) score = 3;
  else score = 4;

  const label = ['very weak', 'weak', 'fair', 'strong', 'very strong'][score];

  // Attacker assumed to try 1e10 guesses per second (offline fast hash).
  const guessesPerSecond = 1e10;
  const guesses = Math.pow(2, entropyBits);
  const crackTimeSeconds = guesses / guessesPerSecond;
  const crackTimeDisplay = humanTime(crackTimeSeconds);

  if (score <= 2 && suggestions.length === 0) {
    suggestions.push('Make it longer and mix character types.');
  }

  return {
    score,
    entropyBits,
    crackTimeSeconds,
    crackTimeDisplay,
    label,
    warnings,
    suggestions,
  };
}
