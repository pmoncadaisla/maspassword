// Password + passphrase generator using the Web Crypto CSPRNG.
// Pure ES module, no external deps — runs in the browser and under Node 22.
// All random picks use rejection sampling to avoid modulo bias.

// Return an unbiased integer in [0, max) using rejection sampling over 32-bit
// values from crypto.getRandomValues. Plain `value % max` would over-represent
// the low end of the range whenever max does not divide 2^32 evenly, so we
// discard the small tail that would cause that bias.
function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0) throw new Error('max must be a positive integer');
  const range = 0x100000000; // 2^32
  const limit = Math.floor(range / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

// Unbiased pick of one character from a string.
function pick(str) {
  return str[randomInt(str.length)];
}

// In-place Fisher-Yates shuffle using unbiased indices.
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }
  return arr;
}

const AMBIGUOUS = 'iIlL1oO0';

// Generate a random password.
// opts: { length=20, upper=true, lower=true, digits=true, symbols=true, avoidAmbiguous=false }
export function generatePassword(opts = {}) {
  const {
    length = 20,
    upper = true,
    lower = true,
    digits = true,
    symbols = true,
    avoidAmbiguous = false,
  } = opts;

  let UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let LOWER = 'abcdefghijklmnopqrstuvwxyz';
  let DIGITS = '0123456789';
  // Symbols never include any of the ambiguous characters.
  const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?';

  if (avoidAmbiguous) {
    const strip = (s) => s.split('').filter((c) => !AMBIGUOUS.includes(c)).join('');
    UPPER = strip(UPPER);
    LOWER = strip(LOWER);
    DIGITS = strip(DIGITS);
  }

  const classes = [];
  if (upper) classes.push(UPPER);
  if (lower) classes.push(LOWER);
  if (digits) classes.push(DIGITS);
  if (symbols) classes.push(SYMBOLS);

  if (classes.length === 0) {
    throw new Error('At least one character class must be enabled');
  }

  const pool = classes.join('');
  const chars = [];

  // Guarantee at least one character from each enabled class, but only when the
  // requested length can actually hold one of each.
  if (length >= classes.length) {
    for (const cls of classes) chars.push(pick(cls));
  }

  while (chars.length < length) chars.push(pick(pool));

  // Shuffle so the guaranteed characters are not always at the front.
  shuffle(chars);

  return chars.join('');
}

// Generate a passphrase from the embedded wordlist.
// opts: { words=4, separator='-', capitalize=false, includeNumber=false }
export function generatePassphrase(opts = {}) {
  const {
    words = 4,
    separator = '-',
    capitalize = false,
    includeNumber = false,
  } = opts;

  const chosen = [];
  for (let i = 0; i < words; i++) {
    let word = WORDLIST[randomInt(WORDLIST.length)];
    if (capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
    chosen.push(word);
  }

  if (includeNumber && chosen.length > 0) {
    const idx = randomInt(chosen.length);
    chosen[idx] = chosen[idx] + randomInt(10);
  }

  return chosen.join(separator);
}

// Approximate entropy in bits using the classic pool model:
//   bits = length * log2(poolSize)
// where poolSize is the sum of the sizes of the character classes present.
export function passwordEntropyBits(pw) {
  if (typeof pw !== 'string' || pw.length === 0) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  if (pool === 0) return 0;
  return pw.length * Math.log2(pool);
}

// Embedded wordlist of short, common English words (deduplicated, >300 entries)
// for offline passphrase generation. log2(len) ~ 8.4 bits of entropy per word.
const WORDLIST = [
  'able', 'acid', 'aged', 'also', 'area', 'army', 'away', 'baby', 'back', 'ball',
  'band', 'bank', 'base', 'bath', 'bear', 'beat', 'been', 'beer', 'bell', 'belt',
  'bend', 'best', 'bird', 'bite', 'blue', 'boat', 'body', 'bone', 'book', 'boot',
  'born', 'boss', 'both', 'bowl', 'bulk', 'burn', 'bush', 'busy', 'cage', 'cake',
  'call', 'calm', 'came', 'camp', 'card', 'care', 'case', 'cash', 'cast', 'cell',
  'chat', 'chip', 'city', 'clay', 'clip', 'club', 'coal', 'coat', 'code', 'cold',
  'come', 'cook', 'cool', 'cope', 'copy', 'core', 'corn', 'cost', 'crew', 'crop',
  'dark', 'data', 'date', 'dawn', 'days', 'dead', 'deal', 'dear', 'debt', 'deep',
  'deer', 'desk', 'dial', 'dice', 'diet', 'dirt', 'dish', 'does', 'done', 'door',
  'dose', 'down', 'draw', 'drew', 'drop', 'drug', 'drum', 'dual', 'duck', 'dull',
  'dust', 'duty', 'each', 'earn', 'ease', 'east', 'easy', 'edge', 'else', 'even',
  'ever', 'evil', 'exit', 'face', 'fact', 'fade', 'fail', 'fair', 'fall', 'farm',
  'fast', 'fate', 'fear', 'feed', 'feel', 'feet', 'fell', 'felt', 'file', 'fill',
  'film', 'find', 'fine', 'fire', 'firm', 'fish', 'fist', 'five', 'flag', 'flat',
  'flee', 'flow', 'folk', 'food', 'foot', 'ford', 'form', 'fort', 'four', 'free',
  'frog', 'fuel', 'full', 'fund', 'gain', 'game', 'gate', 'gave', 'gear', 'gift',
  'girl', 'give', 'glad', 'goal', 'goat', 'gold', 'golf', 'gone', 'good', 'gray',
  'grew', 'grid', 'grip', 'grow', 'gulf', 'hair', 'half', 'hall', 'hand', 'hang',
  'hard', 'harm', 'hate', 'have', 'hawk', 'head', 'hear', 'heat', 'held', 'hell',
  'help', 'herb', 'herd', 'here', 'hero', 'hide', 'high', 'hill', 'hint', 'hire',
  'hold', 'hole', 'holy', 'home', 'hook', 'hope', 'horn', 'host', 'hour', 'huge',
  'hull', 'hunt', 'hurt', 'icon', 'idea', 'inch', 'iron', 'isle', 'item', 'jail',
  'jazz', 'join', 'joke', 'jump', 'jury', 'keen', 'keep', 'kick', 'kind', 'king',
  'kiss', 'kite', 'knee', 'knew', 'knot', 'know', 'lack', 'lady', 'laid', 'lake',
  'lamb', 'lamp', 'land', 'lane', 'last', 'late', 'lawn', 'lazy', 'lead', 'leaf',
  'lean', 'left', 'lend', 'lens', 'less', 'lift', 'like', 'lime', 'line', 'link',
  'lion', 'list', 'live', 'load', 'loan', 'lock', 'loft', 'logo', 'lone', 'long',
  'look', 'loop', 'lord', 'lose', 'loss', 'lost', 'loud', 'love', 'luck', 'lump',
  'lung', 'made', 'mail', 'main', 'make', 'male', 'mall', 'many', 'mark', 'mask',
  'mass', 'mate', 'math', 'meal', 'mean', 'meat', 'meet', 'melt', 'menu', 'mere',
  'mesh', 'mild', 'mile', 'milk', 'mill', 'mind', 'mine', 'mint', 'miss', 'mist',
  'moat', 'mode', 'mold', 'mole', 'mood', 'moon', 'more', 'moss', 'most', 'moth',
  'move', 'much', 'mule', 'must', 'myth', 'nail', 'name', 'navy', 'near', 'neat',
  'neck', 'need', 'nest', 'news', 'next', 'nice', 'node', 'none', 'noon', 'norm',
  'nose', 'note', 'noun', 'oath', 'obey', 'once', 'only', 'onto', 'open', 'oral',
  'oval', 'oven', 'pace', 'pack', 'page', 'paid', 'pain', 'pair', 'pale', 'palm',
  'park', 'part', 'pass', 'past', 'path', 'peak', 'pear', 'peer', 'pile', 'pine',
  'pink', 'pipe', 'plan', 'play', 'plot', 'plug', 'plus', 'poem', 'poet', 'pole',
  'poll', 'pond', 'pony', 'pool', 'poor', 'port', 'pose', 'post', 'pour', 'pray',
  'prep', 'prey', 'prop', 'pull', 'pump', 'pure', 'push', 'quit', 'quiz', 'race',
  'rack', 'rage', 'raid', 'rail', 'rain', 'rank', 'rare', 'rate', 'read', 'real',
  'rear', 'reed', 'reef', 'rely', 'rent', 'rest', 'rice', 'rich', 'ride', 'ring',
  'riot', 'rise', 'risk', 'road', 'roar', 'robe', 'rock', 'role', 'roll', 'roof',
  'room', 'root', 'rope', 'rose', 'ruby', 'rude', 'rule', 'rush', 'sack', 'safe',
  'said', 'sail', 'salt', 'same', 'sand', 'save', 'seal', 'seat', 'seed', 'seek',
  'seem', 'seen', 'self', 'sell', 'send', 'sent', 'ship', 'shoe', 'shop', 'shot',
  'show', 'shut', 'sick', 'side', 'sign', 'silk', 'sing', 'sink', 'site', 'size',
  'skin', 'skip', 'slab', 'slam', 'slid', 'slim', 'slip', 'slot', 'slow', 'snap',
  'snow', 'soap', 'soft', 'soil', 'sold', 'sole', 'some', 'song', 'soon', 'sort',
  'soul', 'soup', 'sour', 'span', 'spin', 'spot', 'star', 'stay', 'stem', 'step',
  'stir', 'stop', 'such', 'suit', 'sure', 'swap', 'swim', 'tail', 'take', 'tale',
  'talk', 'tall', 'tank', 'tape', 'task', 'taxi', 'team', 'tear', 'tell', 'tend',
  'tent', 'term', 'test', 'text', 'than', 'that', 'thaw', 'them', 'then', 'they',
  'thin', 'this', 'thus', 'tide', 'tidy', 'tile', 'till', 'time', 'tiny', 'toll',
  'tone', 'took', 'tool', 'torn', 'tour', 'town', 'trap', 'tray', 'tree', 'trim',
  'trip', 'true', 'tube', 'tuna', 'tune', 'turn', 'twin', 'type', 'ugly', 'undo',
  'unit', 'upon', 'urge', 'used', 'user', 'vary', 'vast', 'veil', 'verb', 'very',
  'vest', 'view', 'visa', 'void', 'vote', 'wage', 'wait', 'wake', 'walk', 'wall',
  'wand', 'want', 'ward', 'warm', 'wash', 'wave', 'weak', 'wear', 'week', 'well',
  'went', 'were', 'west', 'what', 'when', 'whip', 'wide', 'wife', 'wild', 'will',
  'wind', 'wine', 'wing', 'wink', 'wire', 'wise', 'wish', 'wolf', 'wood', 'wool',
  'word', 'wore', 'work', 'worm', 'wrap', 'yard', 'yarn', 'yawn', 'year', 'yell',
  'yoga', 'zero', 'zone', 'zoom',
];
