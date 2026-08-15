// ============================================================
// Sésamo — WebAuthn page hook (MAIN world)
//
// Injected into the page's own JS world at document_start so it can
// replace navigator.credentials.create/get BEFORE the site calls them.
// It cannot use chrome.* APIs; it talks to the isolated-world relay in
// content.js over window.postMessage, which forwards to the background.
//
// Security: this script never decides the origin. It serializes the RP
// options and hands them to the relay; the background derives the real
// origin from chrome.runtime's sender and builds clientDataJSON there.
// A compromised page can lie in the payload but cannot forge its origin.
// ============================================================

(() => {
  if (window.__mpWebauthnHooked) return;
  window.__mpWebauthnHooked = true;

  const NS = '__mpPk';
  const creds = navigator.credentials;
  if (!creds || !window.PublicKeyCredential) return; // no WebAuthn here

  const nativeCreate = creds.create ? creds.create.bind(creds) : null;
  const nativeGet = creds.get ? creds.get.bind(creds) : null;

  // --- base64url <-> ArrayBuffer ---
  const toB64url = buf => {
    const b = new Uint8Array(buf);
    let s = '';
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const fromB64url = str => {
    let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const asBuf = v => v instanceof ArrayBuffer ? v : (ArrayBuffer.isView(v) ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) : null);
  const strToBuf = s => new TextEncoder().encode(String(s)).buffer;

  // --- request/response bridge ---
  // content.js runs later than this script (document_idle vs
  // document_start), so requests made before the relay exists are
  // buffered and flushed when it posts `ready`. This matters for
  // conditional UI, which RPs often invoke on page load.
  let seq = 0;
  let relayReady = false;
  const pending = new Map();
  const outbox = [];
  window.addEventListener('message', ev => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d[NS] !== true) return;
    if (d.dir === 'ready') {
      relayReady = true;
      while (outbox.length) window.postMessage(outbox.shift(), location.origin);
      return;
    }
    if (d.dir !== 'res') return;
    const p = pending.get(d.id);
    if (!p) return;
    pending.delete(d.id);
    p(d.result);
  });
  function post(msg) {
    if (relayReady) window.postMessage(msg, location.origin);
    else outbox.push(msg);
  }
  function ask(kind, payload) {
    const id = NS + ':' + (++seq);
    return new Promise(resolve => {
      pending.set(id, resolve);
      post({ [NS]: true, dir: 'req', id, kind, payload });
    });
  }
  function tell(kind, payload) {
    post({ [NS]: true, dir: 'req', id: null, kind, payload });
  }

  // Build a credential object that reads like a real PublicKeyCredential.
  // The native prototypes are exotic (accessors backed by internal slots),
  // so we set the prototype for instanceof/library checks and define OWN
  // data properties that shadow those accessors.
  function withProto(obj, proto) {
    if (proto) { try { Object.setPrototypeOf(obj, proto); } catch { /* ignore */ } }
    return obj;
  }
  function makeAttestationCredential(r) {
    const rawId = fromB64url(r.credentialId);
    const clientDataJSON = strToBuf(r.clientDataJSON);
    const attestationObject = fromB64url(r.attestationObject);
    const authData = fromB64url(r.authenticatorData);
    const pub = r.publicKey ? fromB64url(r.publicKey) : null;
    const response = withProto({
      clientDataJSON,
      attestationObject,
      getAuthenticatorData: () => authData,
      getPublicKey: () => pub,
      getPublicKeyAlgorithm: () => r.publicKeyAlg,
      getTransports: () => r.transports || ['internal'],
    }, window.AuthenticatorAttestationResponse && window.AuthenticatorAttestationResponse.prototype);
    return withProto({
      id: r.credentialId,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => r.extensions || {},
      toJSON: () => ({
        id: r.credentialId, rawId: r.credentialId, type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: toB64url(clientDataJSON),
          attestationObject: r.attestationObject,
          authenticatorData: r.authenticatorData,
          publicKeyAlgorithm: r.publicKeyAlg,
          publicKey: r.publicKey || undefined,
          transports: r.transports || ['internal'],
        },
        clientExtensionResults: r.extensions || {},
      }),
    }, window.PublicKeyCredential.prototype);
  }
  function makeAssertionCredential(r) {
    const rawId = fromB64url(r.credentialId);
    const clientDataJSON = strToBuf(r.clientDataJSON);
    const authenticatorData = fromB64url(r.authenticatorData);
    const signature = fromB64url(r.signature);
    const userHandle = r.userHandle ? fromB64url(r.userHandle) : null;
    const response = withProto({
      clientDataJSON, authenticatorData, signature, userHandle,
    }, window.AuthenticatorAssertionResponse && window.AuthenticatorAssertionResponse.prototype);
    return withProto({
      id: r.credentialId,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => r.extensions || {},
      toJSON: () => ({
        id: r.credentialId, rawId: r.credentialId, type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: toB64url(clientDataJSON),
          authenticatorData: r.authenticatorData,
          signature: r.signature,
          userHandle: r.userHandle || null,
        },
        clientExtensionResults: r.extensions || {},
      }),
    }, window.PublicKeyCredential.prototype);
  }

  function abortError() {
    return new DOMException('The operation was aborted.', 'AbortError');
  }
  function notAllowed(msg) {
    return new DOMException(msg || 'The operation is not allowed.', 'NotAllowedError');
  }

  // --- navigator.credentials.create ---
  async function create(options) {
    const pk = options && options.publicKey;
    if (!pk || !nativeCreate) return nativeCreate ? nativeCreate(options) : creds.create(options);

    // Defer to the browser when the RP wants something we don't provide:
    // a roaming security key, or an algorithm other than ES256.
    const attachment = pk.authenticatorSelection && pk.authenticatorSelection.authenticatorAttachment;
    const algs = (pk.pubKeyCredParams || []).map(p => p.alg);
    const wantsEs256 = algs.length === 0 || algs.includes(-7);
    if (attachment === 'cross-platform' || !wantsEs256) return nativeCreate(options);

    if (options.signal && options.signal.aborted) throw abortError();

    const payload = {
      challenge: toB64url(asBuf(pk.challenge)),
      rpId: pk.rp && pk.rp.id ? pk.rp.id : undefined,
      rpName: pk.rp && pk.rp.name ? pk.rp.name : undefined,
      userHandle: pk.user ? toB64url(asBuf(pk.user.id)) : undefined,
      userName: pk.user ? pk.user.name : undefined,
      userDisplayName: pk.user ? pk.user.displayName : undefined,
      excludeCredentialIds: (pk.excludeCredentials || []).map(c => toB64url(asBuf(c.id))),
      residentKey: pk.authenticatorSelection && pk.authenticatorSelection.residentKey,
    };

    const result = await raceAbort(ask('create', payload), options.signal);
    if (result && result.fallbackNative) return nativeCreate(options);
    if (!result || !result.ok) throw mapError(result);
    return makeAttestationCredential(result);
  }

  // --- navigator.credentials.get ---
  async function get(options) {
    const pk = options && options.publicKey;
    if (!pk || !nativeGet) return nativeGet ? nativeGet(options) : creds.get(options);
    if (options.signal && options.signal.aborted) throw abortError();

    const payload = {
      challenge: toB64url(asBuf(pk.challenge)),
      rpId: pk.rpId || undefined,
      allowCredentialIds: (pk.allowCredentials || []).map(c => toB64url(asBuf(c.id))),
      mediation: options.mediation || 'optional',
    };

    if (options.mediation === 'conditional') {
      // Conditional UI: no modal. The relay resolves only when the user
      // picks a passkey from an autocomplete="webauthn" field, or stays
      // pending until the RP aborts (per spec, it must not reject early).
      const result = await raceAbort(ask('getConditional', payload), options.signal, () => tell('abortConditional', { challenge: payload.challenge }));
      if (result && result.fallbackNative) return nativeGet(options);
      if (!result || !result.ok) throw mapError(result);
      return makeAssertionCredential(result);
    }

    const result = await raceAbort(ask('get', payload), options.signal);
    if (result && result.fallbackNative) return nativeGet(options);
    if (!result || !result.ok) throw mapError(result);
    return makeAssertionCredential(result);
  }

  function mapError(result) {
    if (result && result.securityError) return new DOMException('The RP ID is not valid for this origin.', 'SecurityError');
    if (result && result.excluded) return new DOMException('A credential already exists.', 'InvalidStateError');
    if (result && result.cancelled) return notAllowed('The user cancelled the request.');
    return notAllowed();
  }

  // Reject as soon as the RP's AbortSignal fires; optionally notify the relay.
  function raceAbort(promise, signal, onAbort) {
    if (!signal) return promise;
    return new Promise((resolve, reject) => {
      const onAb = () => { if (onAbort) onAbort(); reject(abortError()); };
      if (signal.aborted) return onAb();
      signal.addEventListener('abort', onAb, { once: true });
      promise.then(
        v => { signal.removeEventListener('abort', onAb); resolve(v); },
        e => { signal.removeEventListener('abort', onAb); reject(e); });
    });
  }

  // Install the hooks.
  try {
    creds.create = create;
    creds.get = get;
  } catch { /* some environments freeze navigator.credentials */ }

  // Advertise the flows we support so RPs enable passkey + conditional UI.
  try {
    const P = window.PublicKeyCredential;
    P.isUserVerifyingPlatformAuthenticatorAvailable = () => Promise.resolve(true);
    P.isConditionalMediationAvailable = () => Promise.resolve(true);
  } catch { /* ignore */ }
})();
