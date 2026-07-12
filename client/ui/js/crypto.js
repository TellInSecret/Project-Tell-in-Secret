/**
 * CryptoHelper - E2EE 암호화 유틸리티
 * - ECDH P-256 키쌍 생성/교환
 * - AES-GCM-256 암호화/복호화
 * - HKDF 채널 키 파생 (방 키 → 채널 키)
 * - SHA-256 해시 (방 식별키 해싱)
 * - 장기 키쌍 영구 저장/로드
 */
const CryptoHelper = {

  // ─── Key Pair Generation & Persistence ────────────────
  async generateKeyPair() {
    return await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  },

  // Generate and persist a long-term identity key pair
  async generateAndSaveIdentityKeyPair(saveFunc) {
    const kp = await this.generateKeyPair();
    const pubB64 = await this.exportPublicKey(kp.publicKey);
    const privJwk = await window.crypto.subtle.exportKey('jwk', kp.privateKey);
    await saveFunc(pubB64, JSON.stringify(privJwk));
    return kp;
  },

  // Load persisted identity key pair
  async loadIdentityKeyPair(pubB64, privJwkStr) {
    const publicKey = await this.importPublicKey(pubB64);
    const privJwk = JSON.parse(privJwkStr);
    const privateKey = await window.crypto.subtle.importKey(
      'jwk', privJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    return { publicKey, privateKey };
  },

  // ─── Public Key Export/Import ──────────────────────────
  async exportPublicKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    return this.arrayBufferToBase64(exported);
  },

  async importPublicKey(publicKeyBase64) {
    const buffer = this.base64ToArrayBuffer(publicKeyBase64);
    return await window.crypto.subtle.importKey(
      'spki', buffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
  },

  // ─── Shared Key Derivation (ECDH) ─────────────────────
  async deriveSharedKey(privateKey, remotePublicKey) {
    return await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: remotePublicKey },
      privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // ─── Group Key (AES-256) ───────────────────────────────
  async generateGroupKey() {
    return await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  async exportSymmetricKey(key) {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    return this.arrayBufferToBase64(exported);
  },

  async importSymmetricKey(keyBase64) {
    const buffer = this.base64ToArrayBuffer(keyBase64);
    return await window.crypto.subtle.importKey(
      'raw', buffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // ─── Room Key Derivation from Password ────────────────
  // Derives an AES-256 group key from room password + salt.
  // This is the "creative solution" for Discord-style rooms:
  // Anyone who knows the room password can derive the room key locally.
  // Server only stores SHA-256(password) for room lookup.
  async deriveRoomGroupKey(roomPassword, roomSaltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(roomPassword),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
    const saltBytes = this.hexToBytes(roomSaltHex);
    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 200000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // ─── Channel Key Derivation (HKDF from group key) ─────
  // channelKey = HKDF(roomGroupKey, channelId)
  // Server never has this key; channels are isolated cryptographically.
  async deriveChannelKey(roomGroupKey, channelId) {
    // Export group key raw bytes
    const rawGroupKey = await window.crypto.subtle.exportKey('raw', roomGroupKey);

    // Import as HKDF material
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw', rawGroupKey,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const info = new TextEncoder().encode('ticmsg-channel-' + channelId);
    const salt = new Uint8Array(32); // zero salt

    return await window.crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // ─── Encrypt / Decrypt (AES-GCM) ──────────────────────
  async encrypt(key, data) {
    let dataBuffer;
    if (typeof data === 'string') {
      dataBuffer = new TextEncoder().encode(data);
    } else {
      dataBuffer = data;
    }
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBuffer
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.arrayBufferToBase64(combined.buffer);
  },

  async decrypt(key, encryptedBase64, returnRawBuffer = false) {
    const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext.buffer
    );
    if (returnRawBuffer) return decrypted;
    return new TextDecoder().decode(decrypted);
  },

  // ─── SHA-256 Hash (for room key lookup, never original) ─
  async sha256(str) {
    const data = new TextEncoder().encode(str);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  // ─── Fingerprint (SHA-256 of key for visual verification) ─
  async getFingerprint(key) {
    const exported = await window.crypto.subtle.exportKey(
      key.type === 'public' ? 'spki' : 'raw',
      key
    );
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', exported);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const blocks = [];
    for (let i = 0; i < 8; i++) blocks.push(hex.substring(i * 4, (i + 1) * 4));
    return blocks.join('-');
  },

  // ─── Encoding Utilities ────────────────────────────────
  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return window.btoa(binary);
  },

  base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
    return bytes.buffer;
  },

  hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i*2, i*2+2), 16);
    return bytes;
  },
};
