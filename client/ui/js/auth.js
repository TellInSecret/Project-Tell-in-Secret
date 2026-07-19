/**
 * AuthManager - 서버 인증 및 활성화 상태 관리
 * 로컬 저장: Tauri secure storage or localStorage
 */
const AuthManager = {
  // ─── Config ───────────────────────────────────
  serverUrl: 'http://localhost:3000',
  _token: null,
  _username: null,
  _deviceId: null,
  _activated: false,

  // ─── Tauri/localStorage 공통 저장 ──────────────
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

  // ─── Init (앱 시작 시 호출) ─────────────────────
  async init() {
    const configStr = await this._load('auth_config.json');
    if (configStr) {
      try {
        const cfg = JSON.parse(configStr);
        this.serverUrl = cfg.serverUrl || this.serverUrl;
        this._token = cfg.token || null;
        this._username = cfg.username || null;
        this._deviceId = cfg.deviceId || null;
        this._activated = !!cfg.activated;
      } catch (_) {}
    }
    return this._activated;
  },

  // ─── Save config ────────────────────────────────
  async _saveConfig() {
    await this._save('auth_config.json', JSON.stringify({
      serverUrl: this.serverUrl,
      token: this._token,
      username: this._username,
      deviceId: this._deviceId,
      activated: this._activated,
    }));
  },

  // ─── Server URL ──────────────────────────────────
  async setServerUrl(url) {
    this.serverUrl = url.replace(/\/$/, '');
    await this._saveConfig();
  },

  getServerUrl() { return this.serverUrl; },

  // ─── Auth headers ────────────────────────────────
  authHeaders() {
    return {
      'Content-Type': 'application/json',
      ...(this._token ? { 'Authorization': `Bearer ${this._token}` } : {}),
    };
  },

  isLoggedIn() { return !!this._token; },
  isActivated() { return this._activated; },
  getUsername() { return this._username || '사용자'; },
  getDeviceId() { return this._deviceId; },
  getToken() { return this._token; },

  // ─── Activate (클라이언트가 활성화 키 입력) ────────
  async activate(activationKey, publicKeyBase64) {
    const res = await fetch(`${this.serverUrl}/api/activate/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activationKey, publicKey: publicKeyBase64 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '활성화 실패');

    this._token = data.token;
    this._username = data.username;
    this._deviceId = data.deviceId;
    this._activated = true;
    await this._saveConfig();
    return data;
  },

  // ─── Login/Logout ────────────────────────────────
  async logout() {
    this._token = null;
    this._username = null;
    this._deviceId = null;
    this._activated = false;
    await this._saveConfig();
    window.location.reload();
  },

  async login(username, password) {
    const res = await fetch(`${this.serverUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '로그인 실패');

    this._token = data.token;
    this._username = username;
    await this._saveConfig();
    return data;
  },

  // ─── Logout ──────────────────────────────────────
  async logout() {
    this._token = null;
    this._username = null;
    this._deviceId = null;
    this._activated = false;
    await this._saveConfig();
  },

  // ─── API helpers ─────────────────────────────────
  async getDevices() {
    const res = await fetch(`${this.serverUrl}/api/devices`, { headers: this.authHeaders() });
    if (!res.ok) throw new Error('기기 목록 조회 실패');
    return (await res.json()).devices;
  },

  async addDevice(publicKey, deviceName) {
    const res = await fetch(`${this.serverUrl}/api/devices`, {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ publicKey, deviceName }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '기기 등록 실패');
    return data;
  },

  async deleteDevice(deviceId) {
    const res = await fetch(`${this.serverUrl}/api/devices/${deviceId}`, {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    if (!res.ok) throw new Error('기기 삭제 실패');
  },

  // ─── Room API ────────────────────────────────────
  async createRoom(name, roomKeyHash, persistent = false) {
    const res = await fetch(`${this.serverUrl}/api/rooms`, {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ name, roomKeyHash, persistent }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '방 생성 실패');
    return data;
  },

  async getRoom(roomKeyHash) {
    const res = await fetch(`${this.serverUrl}/api/rooms/${roomKeyHash}`, {
      headers: this.authHeaders(),
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('방 정보 조회 실패');
    return res.json();
  },

  async createChannel(roomId, name) {
    const res = await fetch(`${this.serverUrl}/api/rooms/${roomId}/channels`, {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || '채널 생성 실패');
    return data;
  },

  async deleteChannel(roomId, channelId) {
    const res = await fetch(`${this.serverUrl}/api/rooms/${roomId}/channels/${channelId}`, {
      method: 'DELETE',
      headers: this.authHeaders(),
    });
    if (!res.ok) throw new Error('채널 삭제 실패');
  },

  // ─── Persistent message fetch/push ─────────────
  async fetchMessages(channelId, after = 0) {
    const res = await fetch(`${this.serverUrl}/api/messages/${channelId}?after=${after}`, {
      headers: this.authHeaders(),
    });
    if (!res.ok) return [];
    return (await res.json()).messages || [];
  },

  async storeMessage(channelId, ciphertext, sentAt) {
    const res = await fetch(`${this.serverUrl}/api/messages`, {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify({ channelId, ciphertext, sentAt }),
    });
    return res.ok;
  },
};
