/**
 * SignalingClient - WebSocket 기반 서버 시그널링
 * 서버는 WebRTC SDP/ICE 중계만 담당.
 * 실제 채팅 데이터는 직접 P2P DataChannel로 전송.
 */
class SignalingClient {
  constructor(serverUrl, options = {}) {
    this.wsUrl = serverUrl.replace(/^http/, 'ws') + '/';
    this.ws = null;
    this.connected = false;
    this.reconnectDelay = 2000;
    this.maxReconnectDelay = 30000;
    this._reconnectTimer = null;
    this._destroyed = false;

    // Callbacks
    this.onConnected = options.onConnected || (() => {});
    this.onDisconnected = options.onDisconnected || (() => {});
    this.onRoomJoined = options.onRoomJoined || (() => {});
    this.onPeerJoined = options.onPeerJoined || (() => {});
    this.onPeerLeft = options.onPeerLeft || (() => {});
    this.onSignal = options.onSignal || (() => {});
    this.onFriendRequest = options.onFriendRequest || (() => {});
    this.onError = options.onError || (() => {});

    // State
    this.myPeerId = null;
    this._pendingRoom = null;
  }

  // ─── Connect ──────────────────────────────────────
  connect(token, publicKeyBase64, peerId) {
    if (this._destroyed) return;
    this._token = token;
    this._publicKey = publicKeyBase64;
    this._peerId = peerId;
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
      // Authenticate immediately
      this._send({
        type: 'auth',
        token: this._token,
        publicKey: this._publicKey,
        peerId: this._peerId,
      });
    };

    this.ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      this._handleMessage(msg);
    };

    this.ws.onclose = () => {
      this.connected = false;
      this.myPeerId = null;
      this.onDisconnected();
      this._scheduleReconnect();
    };

    this.ws.onerror = () => {
      // onerror always precedes onclose, nothing to do here
    };
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
      case 'auth_ok':
        this.connected = true;
        this.myPeerId = msg.peerId;
        this.onConnected(msg.peerId);
        // Re-join room if we were in one before reconnect
        if (this._pendingRoom) {
          const { roomKeyHash, channelId } = this._pendingRoom;
          this._pendingRoom = null;
          this.joinRoom(roomKeyHash, channelId);
        }
        break;

      case 'auth_error':
        this.onError('인증 오류: ' + msg.error);
        this.destroy();
        break;

      case 'room_joined':
        this.onRoomJoined(msg);
        break;

      case 'peer_joined':
        this.onPeerJoined(msg);
        break;

      case 'peer_left':
        this.onPeerLeft(msg);
        break;

      case 'signal':
        this.onSignal(msg);
        break;

      case 'friend_request':
        this.onFriendRequest(msg);
        break;

      case 'error':
        this.onError(msg.error);
        break;
    }
  }

  _send(obj) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  // ─── Public API ──────────────────────────────────

  joinRoom(roomKeyHash, channelId = null) {
    if (!this.connected) {
      // Queue for after reconnect
      this._pendingRoom = { roomKeyHash, channelId };
      return;
    }
    this._send({ type: 'join_room', roomKeyHash, channelId });
  }

  leaveRoom() {
    this._pendingRoom = null;
    this._send({ type: 'leave_room' });
  }

  switchChannel(channelId) {
    this._send({ type: 'switch_channel', channelId });
  }

  // Send WebRTC signal to a specific peer (via server relay)
  sendSignal(targetPeerId, payload) {
    this._send({ type: 'signal', targetPeerId, payload });
  }

  // Send friend request via server relay
  sendFriendRequest(targetPublicKeyHash, payload) {
    this._send({ type: 'friend_request', targetPublicKeyHash, payload });
  }

  // Push message to server (persistent offline storage)
  storeMessage(channelId, ciphertext, sentAt) {
    this._send({ type: 'store_message', channelId, ciphertext, sentAt });
  }

  // ─── Destroy ─────────────────────────────────────
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
