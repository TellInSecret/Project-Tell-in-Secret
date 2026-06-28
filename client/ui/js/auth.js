/**
 * LocalIdentity - 서버리스 신원 관리 (v2)
 *
 * 기존 AuthManager(서버 의존 JWT 인증)를 완전 대체.
 * 서버 없이 로컬 저장소에만 의존.
 *
 * 방 코드 기반 시스템:
 *  - 사용자명 + ECDH 키쌍만 로컬에 저장
 *  - 방 코드(자동 생성 or 직접 입력)로 방 입장
 *  - 서버 URL, JWT, 활성화 키 등 완전 제거
 */
const LocalIdentity = {
  _username: null,
  _deviceId: null,
  _masterPasswordHash: null, // 로그인 검증용 해시
  _decryptedKeyPair: null,   // 복호화된 CryptoKeyPair 객체 또는 null

  // ─── 저장/로드 (Tauri 또는 localStorage) ────────────────
  async _save(key, value) {
    const invoke = window.__TAURI__?.core?.invoke;
    if (invoke) {
      try { await invoke('save_secure_data', { filename: key, data: value }); return; } catch (_) {}
    }
    localStorage.setItem(key, value);
  },

  async _load(key) {
    const invoke = window.__TAURI__?.core?.invoke;
    if (invoke) {
      try { return await invoke('load_secure_data', { filename: key }); } catch (_) {}
    }
    return localStorage.getItem(key);
  },

  // ─── 초기화 ─────────────────────────────────────────────
  async init() {
    const raw = await this._load('identity.json');
    if (raw) {
      try {
        const data = JSON.parse(raw);
        this._username = data.username || null;
        this._deviceId = data.deviceId || null;
        this._masterPasswordHash = data.passwordHash || null;
      } catch (_) {}
    }
    if (!this._deviceId) {
      this._deviceId = crypto.randomUUID();
      await this._saveIdentity();
    }
    return !!this._username;
  },

  async _saveIdentity() {
    await this._save('identity.json', JSON.stringify({
      username: this._username,
      deviceId: this._deviceId,
      passwordHash: this._masterPasswordHash
    }));
  },

  // ─── PBKDF2 비밀번호 유도 키 생성 ────────────────────────
  async _derivePasswordKey(password, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw', enc.encode(password),
      { name: 'PBKDF2' },
      false, ['deriveKey']
    );
    const saltBytes = CryptoHelper.hexToBytes(saltHex);
    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  // ─── 회원가입 / 신원 새로 만들기 ────────────────────────
  async signUp(username, password) {
    // 1. 새 키쌍 생성
    const kp = await CryptoHelper.generateKeyPair();
    const pubB64 = await CryptoHelper.exportPublicKey(kp.publicKey);
    const privJwk = await window.crypto.subtle.exportKey('jwk', kp.privateKey);

    // 2. 비밀번호 암호화 키 생성 (salt는 deviceId 기반 결정론적 생성)
    const saltHex = await CryptoHelper.sha256(this._deviceId + '-salt');
    const encKey = await this._derivePasswordKey(password, saltHex);

    // 3. Private Key JWK 암호화
    const encryptedPrivJwk = await CryptoHelper.encrypt(encKey, JSON.stringify(privJwk));

    // 4. 로컬 저장소에 저장
    const keypairData = JSON.stringify({ pub: pubB64, privEncrypted: encryptedPrivJwk });
    await this._save('identity_keypair.json', keypairData);

    this._username = username;
    this._masterPasswordHash = await CryptoHelper.sha256(password + saltHex);
    await this._saveIdentity();

    this._decryptedKeyPair = kp;
    return true;
  },

  // ─── 기존 백업 키 복구 가입 ──────────────────────────────
  async signInWithImport(username, password, importedKeypairJson) {
    try {
      const kpData = JSON.parse(importedKeypairJson);
      if (!kpData.pub || !kpData.priv) {
        throw new Error('올바르지 않은 키백업 파일 포맷입니다.');
      }

      // 비밀번호 암호화 키 생성
      const saltHex = await CryptoHelper.sha256(this._deviceId + '-salt');
      const encKey = await this._derivePasswordKey(password, saltHex);

      // Private Key JWK 암호화하여 새로 저장
      const encryptedPrivJwk = await CryptoHelper.encrypt(encKey, kpData.priv);
      const keypairData = JSON.stringify({ pub: kpData.pub, privEncrypted: encryptedPrivJwk });
      await this._save('identity_keypair.json', keypairData);

      // 신원 설정 완료
      this._username = username;
      this._masterPasswordHash = await CryptoHelper.sha256(password + saltHex);
      await this._saveIdentity();

      // 키쌍 로드
      this._decryptedKeyPair = await CryptoHelper.loadIdentityKeyPair(kpData.pub, kpData.priv);
      return true;
    } catch (e) {
      throw new Error('가져오기 실패: ' + e.message);
    }
  },

  // ─── 로그인 / 잠금 해제 (비밀번호 검증 및 키 복호화) ────────
  async login(password) {
    const saltHex = await CryptoHelper.sha256(this._deviceId + '-salt');
    const expectedHash = await CryptoHelper.sha256(password + saltHex);

    if (expectedHash !== this._masterPasswordHash) {
      throw new Error('비밀번호가 올바르지 않습니다.');
    }

    // 암호화된 키쌍 로드
    const rawKp = await this._load('identity_keypair.json');
    if (!rawKp) throw new Error('암호화된 키쌍을 찾을 수 없습니다.');

    const kpData = JSON.parse(rawKp);
    const encKey = await this._derivePasswordKey(password, saltHex);

    // 복호화
    const privJwkStr = await CryptoHelper.decrypt(encKey, kpData.privEncrypted);
    this._decryptedKeyPair = await CryptoHelper.loadIdentityKeyPair(kpData.pub, privJwkStr);
    return true;
  },

  // 백업용 키쌍 텍스트 가져오기 (비밀번호 검증 필수)
  async getBackupPayload(password) {
    const saltHex = await CryptoHelper.sha256(this._deviceId + '-salt');
    const expectedHash = await CryptoHelper.sha256(password + saltHex);
    if (expectedHash !== this._masterPasswordHash) {
      throw new Error('비밀번호가 일치하지 않습니다.');
    }

    const rawKp = await this._load('identity_keypair.json');
    if (!rawKp) throw new Error('키가 존재하지 않습니다.');
    const kpData = JSON.parse(rawKp);
    const encKey = await this._derivePasswordKey(password, saltHex);

    const privJwkStr = await CryptoHelper.decrypt(encKey, kpData.privEncrypted);
    return JSON.stringify({ pub: kpData.pub, priv: privJwkStr }, null, 2);
  },

  // ─── 사용자명 설정 ───────────────────────────────────────
  async setUsername(username) {
    this._username = username;
    await this._saveIdentity();
  },

  getUsername()  { return this._username || '사용자'; },
  getDeviceId()  { return this._deviceId; },
  getDecryptedKeyPair() { return this._decryptedKeyPair || null; },
  async getPublicKeyBase64() {
    if (this._decryptedKeyPair?.publicKey) {
      return await CryptoHelper.exportPublicKey(this._decryptedKeyPair.publicKey);
    }
    const rawKp = await this._load('identity_keypair.json');
    if (!rawKp) return null;
    try {
      const kpData = JSON.parse(rawKp);
      return kpData.pub || null;
    } catch (_) {
      return null;
    }
  },
  isSetup()      { return !!this._username; },
  isActivated()  { return this.isSetup(); }, // 하위 호환성 유지

  // Server API Compatibility Mock (no-op or defaults since we are serverless)
  getServerUrl() { return localStorage.getItem('server_url') || 'ws://localhost:3000'; },
  setServerUrl(url) { localStorage.setItem('server_url', url); },
  getToken()     { return 'serverless-token'; },

  // ─── 방 코드 히스토리 (최근 방 목록) ─────────────────────
  async getRoomHistory() {
    const raw = await this._load('room_history.json');
    try { return raw ? JSON.parse(raw) : []; } catch { return []; }
  },

  async addRoomToHistory(roomCode, roomName) {
    const history = await this.getRoomHistory();
    const filtered = history.filter(r => r.code !== roomCode);
    filtered.unshift({ code: roomCode, name: roomName, lastVisited: Date.now() });
    const trimmed = filtered.slice(0, 20);
    await this._save('room_history.json', JSON.stringify(trimmed));
  },

  async removeRoomFromHistory(roomCode) {
    const history = await this.getRoomHistory();
    const filtered = history.filter(r => r.code !== roomCode);
    await this._save('room_history.json', JSON.stringify(filtered));
  },
};

// 하위 호환을 위한 별칭
const AuthManager = LocalIdentity;

