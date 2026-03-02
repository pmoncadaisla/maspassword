// SRP-6a client implementation - exact match with github.com/opencoff/go-srp v0.6.7
// Uses BLAKE2b-256 as hash, RFC 5054 2048-bit group
//
// Key implementation details from go-srp source:
//   x = H(I_hash, P_hash, salt)       — identity first, then password, then salt
//   k = H(N.Bytes(), pad(g))          — N unpadded, g padded
//   u = H(pad(A), pad(B))            — both padded
//   K = H(S.Bytes())                  — S unpadded (minimal big-endian)
//   M = H(K, A.Bytes(), B.Bytes(), I, salt, N.Bytes(), g.Bytes()) — all unpadded
//   ServerProof = H(K, M)             — K first, then M

const N_HEX = 'ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73';
const N = BigInt('0x' + N_HEX);
const g = 2n;
const fieldSize = N_HEX.length / 2; // 256 bytes

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Equivalent to Go's big.Int.Bytes() — minimal big-endian representation, no leading zeros
function bigintToMinBytes(n) {
  if (n === 0n) return new Uint8Array([0]);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return hexToBytes(hex);
}

// Equivalent to Go's pad(x, n) — pad to exactly fieldSize bytes
function pad(n) {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  while (hex.length < fieldSize * 2) hex = '00' + hex;
  return hexToBytes(hex);
}

// H(...inputs) = BLAKE2b-256(input1 || input2 || ...) — all inputs are byte arrays
function H(...byteArrays) {
  return blake2b256Multi(...byteArrays);
}

function HBigInt(...byteArrays) {
  const hash = H(...byteArrays);
  return BigInt('0x' + bytesToHex(hash));
}

function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function randomBigInt(bits) {
  const bytes = bits / 8;
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return BigInt('0x' + bytesToHex(arr));
}

// k = H(N.Bytes(), pad(g)) — matches go-srp exactly
function computeK() {
  return HBigInt(bigintToMinBytes(N), pad(g));
}

export class SRPClient {
  constructor(identity, password) {
    this.ih = blake2b256(identity);  // H(I) as bytes
    this.ph = blake2b256(password);  // H(P) as bytes
    this.a = randomBigInt(fieldSize * 8); // random private key (same bit size as N)
    this.A = modPow(g, this.a, N);
    this.k = computeK();
  }

  // Returns credentials: "identity_hex:A_hex" — matches go-srp Client.Credentials()
  credentials() {
    return bytesToHex(this.ih) + ':' + bytesToHex(bigintToMinBytes(this.A));
  }

  // Process server credentials and generate proof
  // serverCreds format: "salt_hex:B_hex"
  generate(serverCreds) {
    const parts = serverCreds.split(':');
    if (parts.length !== 2) throw new Error('Invalid server credentials');

    this.salt = hexToBytes(parts[0]);
    this.B = BigInt('0x' + parts[1]);

    if (this.B % N === 0n) throw new Error('Invalid B value');

    // u = H(pad(A), pad(B))
    const u = HBigInt(pad(this.A), pad(this.B));
    if (u === 0n) throw new Error('Invalid u value');

    // x = H(I_hash, P_hash, salt) — go-srp order: identity, password, salt
    const x = HBigInt(this.ih, this.ph, this.salt);

    // S = (B - k * g^x)^(a + u*x) mod N
    const gx = modPow(g, x, N);
    let t1 = (this.B - this.k * gx) % N;
    if (t1 < 0n) t1 += N;
    const t2 = this.a + u * x;
    const S = modPow(t1, t2, N);

    // K = H(S.Bytes()) — S unpadded
    this.K = H(bigintToMinBytes(S));

    // M = H(K, A.Bytes(), B.Bytes(), I, salt, N.Bytes(), g.Bytes()) — all unpadded
    this.M = H(
      this.K,
      bigintToMinBytes(this.A),
      bigintToMinBytes(this.B),
      this.ih,
      this.salt,
      bigintToMinBytes(N),
      bigintToMinBytes(g)
    );

    return bytesToHex(this.M);
  }

  // Verify server proof: Z = H(K, M) — K first, then M
  serverOk(serverProof) {
    const expected = bytesToHex(H(this.K, this.M));
    return expected === serverProof;
  }
}

// Generate verifier for signup — matches go-srp Verifier() + Encode()
export function generateVerifier(identity, password) {
  const ih = blake2b256(identity);  // H(I)
  const ph = blake2b256(password);  // H(P)

  // salt = random bytes (fieldSize = 256 bytes, same as go-srp randbytes(pf.n))
  const salt = new Uint8Array(fieldSize);
  crypto.getRandomValues(salt);

  // x = H(I_hash, P_hash, salt) — same order as go-srp
  const x = HBigInt(ih, ph, salt);

  // v = g^x mod N
  const v = modPow(g, x, N);

  // Encode in go-srp format: "fieldSizeBytes:N_hex:g_hex:hashId:I_hex:salt_hex:v_hex"
  // fieldSizeBytes = 256, hashId = 17 (crypto.BLAKE2b_256)
  const ihHex = bytesToHex(ih);
  const saltHex = bytesToHex(salt);
  const vHex = bytesToHex(bigintToMinBytes(v));
  const encoded = `256:${N_HEX}:2:17:${ihHex}:${saltHex}:${vHex}`;

  return { identity: ihHex, verifier: encoded, salt: saltHex };
}
