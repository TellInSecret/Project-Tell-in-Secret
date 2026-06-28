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
    }));
  },

  // ─── 사용자명 설정 ───────────────────────────────────────
  async setUsername(username) {
    this._username = username;
    await this._saveIdentity();
  },

  getUsername()  { return this._username || '사용자'; },
  getDeviceId()  { return this._deviceId; },
  isSetup()      { return !!this._username; },

  // ─── 방 코드 히스토리 (최근 방 목록) ─────────────────────
  async getRoomHistory() {
    const raw = await this._load('room_history.json');
    try { return raw ? JSON.parse(raw) : []; } catch { return []; }
  },

  async addRoomToHistory(roomCode, roomName) {
    const history = await this.getRoomHistory();
    // 중복 제거 후 앞에 추가
    const filtered = history.filter(r => r.code !== roomCode);
    filtered.unshift({ code: roomCode, name: roomName, lastVisited: Date.now() });
    // 최대 20개 유지
    const trimmed = filtered.slice(0, 20);
    await this._save('room_history.json', JSON.stringify(trimmed));
  },

  async removeRoomFromHistory(roomCode) {
    const history = await this.getRoomHistory();
    const filtered = history.filter(r => r.code !== roomCode);
    await this._save('room_history.json', JSON.stringify(filtered));
  },
};

// 하위 호환을 위한 별칭 (기존 코드에서 AuthManager를 참조할 경우)
const AuthManager = LocalIdentity;
