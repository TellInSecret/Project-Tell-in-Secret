/**
 * FriendCode Module
 * - ECDH Public Key → Base58 Friend Code
 * - SDP Compression (CompressionStream / deflate-raw)
 * - Compressed Invite / Answer Packet Building
 * - Challenge-Response Mutual Authentication
 * - Local Friend List Persistence
 */
const FriendCode = {
  // Bitcoin-style Base58 alphabet (no 0, O, I, l to avoid visual confusion)
  BASE58_CHARS: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',

  // ============================================================
  // Base58 Encoding / Decoding
  // ============================================================

  encodeBase58(buffer) {
    const bytes = new Uint8Array(buffer);
    let leadingZeros = 0;
    for (const b of bytes) {
      if (b !== 0) break;
      leadingZeros++;
    }
    // Convert bytes to BigInt
    let num = 0n;
    for (const b of bytes) {
      num = num * 256n + BigInt(b);
    }
    // Convert BigInt to Base58
    let result = '';
    const base = 58n;
    while (num > 0n) {
      const remainder = num % base;
      num /= base;
      result = this.BASE58_CHARS[Number(remainder)] + result;
    }
    return '1'.repeat(leadingZeros) + result;
  },

  decodeBase58(str) {
    let leadingZeros = 0;
    for (const ch of str) {
      if (ch !== '1') break;
      leadingZeros++;
    }
    let num = 0n;
    const base = 58n;
    for (const ch of str) {
      const idx = this.BASE58_CHARS.indexOf(ch);
      if (idx === -1) throw new Error(`Invalid Base58 character: ${ch}`);
      num = num * base + BigInt(idx);
    }
    // Convert BigInt to bytes
    let hex = num.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const decoded = new Uint8Array(hex.length / 2);
    for (let i = 0; i < decoded.length; i++) {
      decoded[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    const result = new Uint8Array(leadingZeros + decoded.length);
    result.set(decoded, leadingZeros);
    return result.buffer;
  },

  // ============================================================
  // Friend Code <-> Public Key Conversion
  // ============================================================

  // Generate friend code from ECDH public key (spki export → Base58 → grouped)
  async generateMyFriendCode(publicKey) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    const raw = this.encodeBase58(exported);
    return this.formatCode(raw);
  },

  // Parse friend code back into importable CryptoKey
  async parseFriendCode(code) {
    const cleaned = code.replace(/-|\s/g, '').trim();
    const buffer = this.decodeBase58(cleaned);
    return await window.crypto.subtle.importKey(
      'spki',
      buffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [] // public key: no usages
    );
  },

  // Get raw base58 string (no dashes) from code
  getRawCode(code) {
    return code.replace(/-|\s/g, '').trim();
  },

  // Format a Base58 string into groups of 5 characters for readability
  formatCode(raw) {
    return raw.match(/.{1,5}/g).join('-');
  },

  // ============================================================
  // SDP Compression (CompressionStream - deflate-raw)
  // ============================================================

  async compress(str) {
    const inputStream = new Blob([new TextEncoder().encode(str)]).stream();
    const compressedStream = inputStream.pipeThrough(new CompressionStream('deflate-raw'));
    const chunks = [];
    const reader = compressedStream.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return CryptoHelper.arrayBufferToBase64(result.buffer);
  },

  async decompress(compressedBase64) {
    const buffer = CryptoHelper.base64ToArrayBuffer(compressedBase64);
    const inputStream = new Blob([new Uint8Array(buffer)]).stream();
    const decompressedStream = inputStream.pipeThrough(new DecompressionStream('deflate-raw'));
    const chunks = [];
    const reader = decompressedStream.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
    return new TextDecoder().decode(result);
  },

  // ============================================================
  // Invite / Answer Packet Building
  // ============================================================

  // Build compressed connection invite packet (Offer side)
  async buildInvitePacket(sdpOffer, myPublicKey, myPeerId, myUsername) {
    const pubKeyStr = await CryptoHelper.exportPublicKey(myPublicKey);
    const payload = JSON.stringify({
      v: 1,
      type: 'invite',
      peerId: myPeerId,
      username: myUsername,
      publicKey: pubKeyStr,
      sdp: sdpOffer
    });
    return await this.compress(payload);
  },

  async parseInvitePacket(packetStr) {
    const raw = await this.decompress(packetStr.trim());
    return JSON.parse(raw);
  },

  // Build compressed connection answer packet (Answer side)
  async buildAnswerPacket(sdpAnswer, myPublicKey, myPeerId, myUsername) {
    const pubKeyStr = await CryptoHelper.exportPublicKey(myPublicKey);
    const payload = JSON.stringify({
      v: 1,
      type: 'answer',
      peerId: myPeerId,
      username: myUsername,
      publicKey: pubKeyStr,
      sdp: sdpAnswer
    });
    return await this.compress(payload);
  },

  async parseAnswerPacket(packetStr) {
    const raw = await this.decompress(packetStr.trim());
    return JSON.parse(raw);
  },

  // ============================================================
  // Challenge-Response Mutual Authentication
  // After WebRTC DataChannel opens, both sides prove they hold
  // the same ECDH-derived shared key via encrypted nonce exchange.
  // ============================================================

  generateChallenge() {
    const nonce = window.crypto.getRandomValues(new Uint8Array(32));
    return CryptoHelper.arrayBufferToBase64(nonce.buffer);
  },

  // Encrypt our nonce with the shared key to produce our response to peer's challenge
  async respondToChallenge(challengeBase64, sharedKey) {
    return await CryptoHelper.encrypt(sharedKey, challengeBase64);
  },

  // Verify peer's response decrypts to the expected nonce
  async verifyResponse(expectedChallengeBase64, responseEncrypted, sharedKey) {
    try {
      const decrypted = await CryptoHelper.decrypt(sharedKey, responseEncrypted);
      return decrypted === expectedChallengeBase64;
    } catch {
      return false;
    }
  },

  // ============================================================
  // Local Friend List Persistence (Tauri or localStorage fallback)
  // ============================================================

  _friends: null, // Cache

  async loadFriends() {
    if (this._friends) return this._friends;
    let data = null;
    const invoke = window.__TAURI__?.core?.invoke;
    if (invoke) {
      try { data = await invoke('load_secure_data', { filename: 'friends.json' }); } catch (_) {}
    } else {
      data = localStorage.getItem('ticmsg_friends');
    }
    try { this._friends = data ? JSON.parse(data) : {}; } catch { this._friends = {}; }
    return this._friends;
  },

  async saveFriends() {
    const data = JSON.stringify(this._friends);
    const invoke = window.__TAURI__?.core?.invoke;
    if (invoke) {
      try { await invoke('save_secure_data', { filename: 'friends.json', data }); } catch (_) {}
    } else {
      localStorage.setItem('ticmsg_friends', data);
    }
  },

  async addFriend(peerId, username, friendCodeRaw, fingerprint) {
    if (!this._friends) await this.loadFriends();
    this._friends[peerId] = {
      username,
      friendCode: friendCodeRaw,
      fingerprint,
      addedAt: new Date().toISOString()
    };
    await this.saveFriends();
    return this._friends[peerId];
  },

  async removeFriend(peerId) {
    if (!this._friends) await this.loadFriends();
    delete this._friends[peerId];
    await this.saveFriends();
  },

  async getFriendList() {
    if (!this._friends) await this.loadFriends();
    return Object.entries(this._friends).map(([peerId, info]) => ({ peerId, ...info }));
  },

  isFriend(peerId) {
    return this._friends && !!this._friends[peerId];
  }
};
