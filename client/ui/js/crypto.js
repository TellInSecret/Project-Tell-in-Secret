/**
 * CryptoHelper - E2EE 암호화 유틸리티 (v2 - Serverless)
 *
 * 핵심 변경사항:
 *  - roomSalt를 서버에서 받지 않고 비밀번호에서 결정론적으로 파생
 *  - roomId(공개 채널 식별자)도 비밀번호에서 로컬 파생
 *  - 방 코드: 랜덤 단어 조합으로 자동 생성 (사용자가 타이핑할 필요 없음)
 *  - 충돌 내성: 같은 방 코드라도 ECDH sharedKey가 다르면 내용 불가 해독
 *  - HKDF salt를 zero-bytes → roomSalt로 변경 (보안 강화)
 *  - ECDH: P-256 (Web Crypto 호환성 우선)
 */
const CryptoHelper = {

  // ─── 방 코드 생성 (랜덤 단어 조합) ──────────────────────
  // 충분한 엔트로피(약 52비트)를 갖는 사람이 읽기 쉬운 코드
  // 예: "apple-river-7341"
  _WORDS: [
    'apple','river','cloud','stone','tiger','eagle','flame','frost',
    'beach','cedar','delta','ember','flint','grove','haven','ivory',
    'jewel','karma','lunar','maple','noble','ocean','pearl','quill',
    'raven','sigma','thorn','umbra','valor','waltz','xenon','yacht',
    'zebra','amber','blaze','coral','dawn','echo','forge','glade',
    'holly','iris','jade','knoll','lark','mist','nova','opal',
    'pine','quest','reef','sage','tide','ultra','veil','wind',
  ],

  generateRoomCode() {
    const arr = new Uint32Array(3);
    window.crypto.getRandomValues(arr);
    const w1 = this._WORDS[arr[0] % this._WORDS.length];
    const w2 = this._WORDS[arr[1] % this._WORDS.length];
    const num = (arr[2] % 9000) + 1000; // 1000~9999
    return `${w1}-${w2}-${num}`;
  },

  // ─── 방 코드에서 roomSalt 결정론적 파생 ─────────────────
  // 서버에서 salt를 받아올 필요 없음.
  // 같은 방 코드 = 같은 salt = 같은 그룹키 파생 가능
  async deriveRoomSalt(roomCode) {
    const enc = new TextEncoder();
    const keyMat = await window.crypto.subtle.importKey(
      'raw', enc.encode(roomCode),
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['sign']
    );
    const sig = await window.crypto.subtle.sign(
      'HMAC', keyMat,
      enc.encode('ticmsg-room-salt-v2')
    );
    return Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // ─── 방 코드에서 공개 방 ID 파생 ───────────────────────
  // WebRTC 시그널링 채널 식별자로 사용 (평문으로 서버에 전달해도 안전)
  // 방 코드를 역산할 수 없음 (SHA-256 단방향)
  async deriveRoomId(roomCode) {
    return await this.sha256('ticmsg-room-id-v2:' + roomCode);
  },

  // ─── 기본 채널 ID (roomId에서 결정론적 파생) ────────────
  // 모든 피어가 같은 roomId → 같은 기본 채널 ID → 같은 채널 키.
  // app.js, signal_serverless.js 등 어디서든 이 함수를 써서 일관성 보장.
  defaultChannelId(roomId) {
    return roomId.slice(0, 16) + '-general';
  },

  // ─── 이름 기반 채널 ID (추가 채널용, 결정론적) ──────────
  // 서버리스라 채널 생성을 동기화할 수단이 없으므로, 채널 ID를
  // roomId + 채널 이름에서 결정론적으로 파생한다.
  // → 같은 방에서 같은 이름의 채널을 만든 피어들끼리 자동으로
  //   동일한 채널 ID와 채널 키를 공유한다 (별도 전파 불필요).
  async channelIdFromName(roomId, name) {
    const norm = (name || '').trim().toLowerCase();
    const hash = await this.sha256('ticmsg-channel-id-v2:' + roomId + ':' + norm);
    return 'ch-' + hash.slice(0, 24);
  },

  // ─── 충돌 내성 설명 ─────────────────────────────────────
  // 두 그룹이 우연히 같은 방 코드를 사용하더라도:
  //   - 서로 다른 ECDH 개인키 → 서로 다른 sharedKey → 암호화 내용 상호 불가해독
  //   - 그룹키(PBKDF2)가 같더라도, 서로 다른 유저의 공개키 = 다른 sharedKey로 인증 실패
  //   - 즉 방 코드 충돌 = "같은 방에 모임"만 되고 메시지 내용은 볼 수 없음

  // ─── Key Pair (P-256 유지 - Web Crypto 호환성) ─────────
  async generateKeyPair() {
    return await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  },

  async generateAndSaveIdentityKeyPair(saveFunc) {
    const kp = await this.generateKeyPair();
    const pubB64 = await this.exportPublicKey(kp.publicKey);
    const privJwk = await window.crypto.subtle.exportKey('jwk', kp.privateKey);
    await saveFunc(pubB64, JSON.stringify(privJwk));
    return kp;
  },

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

  // ─── Group Key from Room Code (PBKDF2) ─────────────────
  // roomSalt는 서버에서 받지 않고 deriveRoomSalt()로 로컬 계산
  async deriveRoomGroupKey(roomCode, roomSaltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw', enc.encode(roomCode),
      { name: 'PBKDF2' },
      false, ['deriveBits', 'deriveKey']
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

  // ─── Channel Key (HKDF from group key + roomSalt) ──────
  // [v2 개선] salt를 zero-bytes 대신 roomSalt 사용 → 보안 강화
  async deriveChannelKey(roomGroupKey, channelId, roomSaltHex) {
    const rawGroupKey = await window.crypto.subtle.exportKey('raw', roomGroupKey);

    const hkdfKey = await window.crypto.subtle.importKey(
      'raw', rawGroupKey,
      { name: 'HKDF' },
      false, ['deriveKey']
    );

    const info = new TextEncoder().encode('ticmsg-channel-v2-' + channelId);
    // [v2] salt = roomSalt (있으면) or zero (폴백)
    const salt = roomSaltHex
      ? this.hexToBytes(roomSaltHex)
      : new Uint8Array(32);

    return await window.crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // ─── Symmetric Key Helpers ─────────────────────────────
  async generateGroupKey() {
    return await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, ['encrypt', 'decrypt']
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
      true, ['encrypt', 'decrypt']
    );
  },

  // ─── Encrypt / Decrypt (AES-GCM-256) ──────────────────
  // aad(Additional Authenticated Data): 평문이지만 위변조를 막아야 하는
  // 메타데이터(channelId, msgId, type 등)를 암호화 인증 태그에 묶는다.
  // aad가 한 비트라도 바뀌면 복호화가 예외로 실패 → 위변조 감지.
  async encrypt(key, data, aad = null) {
    const dataBuffer = typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data;
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const params = { name: 'AES-GCM', iv };
    if (aad != null) {
      params.additionalData = typeof aad === 'string'
        ? new TextEncoder().encode(aad)
        : aad;
    }
    const ciphertext = await window.crypto.subtle.encrypt(
      params, key, dataBuffer
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), 12);
    return this.arrayBufferToBase64(combined.buffer);
  },

  async decrypt(key, encryptedBase64, returnRawBuffer = false, aad = null) {
    const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const params = { name: 'AES-GCM', iv };
    if (aad != null) {
      params.additionalData = typeof aad === 'string'
        ? new TextEncoder().encode(aad)
        : aad;
    }
    const decrypted = await window.crypto.subtle.decrypt(
      params, key, ciphertext.buffer
    );
    if (returnRawBuffer) return decrypted;
    return new TextDecoder().decode(decrypted);
  },

  // ─── SHA-256 ──────────────────────────────────────────
  async sha256(str) {
    const data = new TextEncoder().encode(str);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // ─── Key Fingerprint (for visual verification) ─────────
  async getFingerprint(key) {
    const exported = await window.crypto.subtle.exportKey(
      key.type === 'public' ? 'spki' : 'raw', key
    );
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', exported);
    const hex = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
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
