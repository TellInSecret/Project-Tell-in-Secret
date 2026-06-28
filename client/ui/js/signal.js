/**
 * SignalingClient v2 - 경량 WebSocket 시그널링 클라이언트
 *
 * v1 대비 변경:
 *  - JWT 인증 제거 (auth 핸드셰이크 없음)
 *  - roomKeyHash → roomId (클라이언트가 직접 파생한 SHA-256)
 *  - 서버 메시지 저장 기능 제거 (영구 저장 없음)
 *  - 친구 요청 서버 릴레이 제거 (직접 P2P로 처리)
 *  - ServerlessSignaling과 동일한 인터페이스 유지
 */
class SignalingClient {
  constructor(serverUrl, options = {}) {
    this.wsUrl = serverUrl.replace(/^http/, 'ws').replace(/\/?$/, '/');
    this.ws    = null;
    this.connected       = false;
    this.reconnectDelay  = 2000;
    this.maxReconnectDelay = 30000;
    this._reconnectTimer = null;
    this._destroyed      = false;

    // Callbacks
    this.onConnected    = options.onConnected    || (() => {});
    this.onDisconnected = options.onDisconnected || (() => {});
    this.onRoomJoined   = options.onRoomJoined   || (() => {});
    this.onPeerJoined   = options.onPeerJoined   || (() => {});
    this.onPeerLeft     = options.onPeerLeft     || (() => {});
    this.onSignal       = options.onSignal       || (() => {});
    this.onError        = options.onError        || (() => {});

    // State
    this.myPeerId   = null;
    this._peerId    = null;
    this._publicKey = null;
    this._username  = null;
    this._pendingRoom = null;  // { roomCode, roomId, roomSalt, roomName }
  }

  // ─── 연결 ──────────────────────────────────────────────
  connect(peerId, publicKeyBase64, username) {
    if (this._destroyed) return;
    this._peerId    = peerId;
    this._publicKey = publicKeyBase64;
    this._username  = username || '사용자';
    this._openSocket();
  }

  _openSocket() {
    if (this._destroyed) return;
    try {
      this.ws = new WebSocket(this.wsUrl);
    } catch (e) {
      this._scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectDelay = 2000;
      this.connected = true;
      this.myPeerId  = this._peerId;
      this.onConnected(this._peerId);

      // 재연결 시 방 재입장
      if (this._pendingRoom) {
        const r = this._pendingRoom;
        this._pendingRoom = null;
        this.joinRoom(r.roomCode, r.roomId, r.roomSalt, r.roomName);
      }
    };

    this.ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      this._handleMessage(msg);
    };

    this.ws.onclose = () => {
      this.connected = false;
      this.myPeerId  = null;
      this.onDisconnected();
      this._scheduleReconnect();
    };

    this.ws.onerror = () => {};
  }

  _scheduleReconnect() {
    if (this._destroyed) return;
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(() => {
      this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, this.maxReconnectDelay);
      this._openSocket();
    }, this.reconnectDelay);
  }

  _handleMessage(msg) {
    switch (msg.type) {
      case 'joined': {
        // 서버가 피어 목록과 함께 입장 확인
        const room = this._currentRoom;
        if (!room) return;
        this.onRoomJoined({
          roomId:     room.roomId,
          roomName:   room.roomName,
          roomSalt:   room.roomSalt,
          persistent: false,
          channels:   room.channels || [{ id: room.roomId.slice(0, 16) + '-general', name: '일반', position: 0 }],
          peers:      msg.peers || [],
        });
        break;
      }
      case 'peer_joined':
        this.onPeerJoined(msg);
        break;
      case 'peer_left':
        this.onPeerLeft(msg);
        break;
      case 'signal':
        this.onSignal(msg);
        break;
      case 'error':
        this.onError(msg.error || '서버 오류');
        break;
    }
  }

  _send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  // ─── 공개 API ───────────────────────────────────────────

  /**
   * 방 입장.
   * @param {string} roomCode  - 방 코드 (비밀, 서버에 전달 안 함)
   * @param {string} roomId    - SHA-256(방코드) (공개 식별자)
   * @param {string} roomSalt  - 로컬 파생 salt
   * @param {string} roomName  - 방 표시 이름
   */
  joinRoom(roomCode, roomId, roomSalt, roomName = '') {
    if (!this.connected) {
      this._pendingRoom = { roomCode, roomId, roomSalt, roomName };
      return;
    }

    // 채널 정보는 로컬에서 계산
    const defaultChannelId = roomId.slice(0, 16) + '-general';
    this._currentRoom = {
      roomId,
      roomName: roomName || roomCode,
      roomSalt,
      channels: [{ id: defaultChannelId, name: '일반', position: 0 }],
    };

    // 서버에는 roomId(공개 해시)만 전달 — 방 코드(비밀)는 절대 전달 안 함
    this._send({
      type:      'join',
      roomId,
      peerId:    this._peerId,
      username:  this._username,
      publicKey: this._publicKey,
    });
  }

  leaveRoom() {
    this._pendingRoom = null;
    this._currentRoom = null;
    this._send({ type: 'leave' });
  }

  switchChannel(channelId) {
    // 서버리스 채널 전환: 클라이언트 로컬로만 처리
  }

  sendSignal(targetPeerId, payload) {
    this._send({ type: 'signal', targetPeerId, payload });
  }

  // 영구 저장 없음 (no-op)
  storeMessage() {}

  // ─── 해제 ───────────────────────────────────────────────
  destroy() {
    this._destroyed = true;
    clearTimeout(this._reconnectTimer);
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
    this.connected = false;
  }
}
