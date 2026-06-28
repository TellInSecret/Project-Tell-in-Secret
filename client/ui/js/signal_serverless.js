/**
 * ServerlessSignaling - 서버 없는 WebRTC 시그널링 (v2)
 *
 * 3단계 폴백 전략:
 *   1. PeerJS 공개 브로커 (무료, 비식별, 비인증)
 *      - roomId(=SHA-256(방코드))를 채널로 사용
 *      - 실제 채팅 데이터는 WebRTC DataChannel로만 전송
 *   2. 수동 교환 (완전 오프라인)
 *      - buildInvitePacket / buildAnswerPacket (friendcode.js)
 *      - QR코드 or 텍스트 복사/붙여넣기
 *
 * SignalingClient(signal.js)와 동일한 인터페이스를 구현하여 p2p.js가
 * 시그널링 방식에 무관하게 동작한다.
 *
 * 방 코드 충돌 내성:
 *   같은 roomId를 사용하는 다른 그룹이 있어도 ECDH sharedKey가 다르므로
 *   DataChannel 열린 후 상호 인증(challenge-response)에서 걸러진다.
 */

const PEERJS_HOST = '0.peerjs.com';   // PeerJS 공개 서버 (https://github.com/peers/peerjs-server)
const PEERJS_PORT = 443;
const PEERJS_PATH = '/';

class ServerlessSignaling {
  constructor(options = {}) {
    this._options = options;

    // Callbacks (SignalingClient 인터페이스 호환)
    this.onConnected      = options.onConnected      || (() => {});
    this.onDisconnected   = options.onDisconnected   || (() => {});
    this.onRoomJoined     = options.onRoomJoined     || (() => {});
    this.onPeerJoined     = options.onPeerJoined     || (() => {});
    this.onPeerLeft       = options.onPeerLeft       || (() => {});
    this.onSignal         = options.onSignal         || (() => {});
    this.onError          = options.onError          || (() => {});

    this.myPeerId    = null;     // 내 PeerJS peer ID
    this._peer       = null;     // PeerJS Peer 객체
    this._roomId     = null;     // SHA-256(방코드) - 공개 방 식별자
    this._roomCode   = null;     // 원본 방 코드 (비밀)
    this._roomName   = '';
    this._roomSalt   = '';

    // peerId -> DataConnection (시그널링용, 채팅용 아님)
    this._sigConns   = {};

    // 방에 있는 피어 목록 (브로드캐스트로 공유)
    this._roomPeers  = {};       // peerId -> { username, publicKey }

    this._mode       = 'peerjs'; // 'peerjs' | 'manual'
    this._destroyed  = false;

    // 수동 교환 모드용 콜백
    this.onManualInviteReady  = options.onManualInviteReady  || (() => {});
    this.onManualAnswerReady  = options.onManualAnswerReady  || (() => {});

    // 오프라인 p2p (manual) 연결 관리
    this._manualPc   = null;
    this._manualDc   = null;
  }

  // ─── 모드 1: PeerJS 브로커 기반 자동 연결 ───────────────

  /**
   * PeerJS 브로커에 연결. 비인증, 방 코드 기반 식별.
   * @param {string} peerId  - 내 고유 PeerJS ID (UUID)
   * @param {string} publicKeyBase64 - 내 공개키
   */
  connect(peerId, publicKeyBase64) {
    if (this._destroyed) return;
    this._mode = 'peerjs';
    this.myPeerId = peerId;
    this._myPublicKey = publicKeyBase64;

    // PeerJS 라이브러리 확인
    if (typeof Peer === 'undefined') {
      console.warn('[Signaling] PeerJS not loaded, falling back to manual mode');
      this._mode = 'manual';
      this.onConnected(peerId);
      return;
    }

    this._peer = new Peer(peerId, {
      host: PEERJS_HOST,
      port: PEERJS_PORT,
      path: PEERJS_PATH,
      secure: true,
    });

    this._peer.on('open', (id) => {
      this.myPeerId = id;
      this.onConnected(id);
    });

    this._peer.on('connection', (conn) => {
      // 다른 피어가 나에게 시그널링 연결을 걸어왔을 때
      this._setupSigConn(conn);
    });

    this._peer.on('disconnected', () => {
      this.onDisconnected();
      if (!this._destroyed) this._peer.reconnect();
    });

    this._peer.on('error', (err) => {
      console.error('[PeerJS]', err);
      if (err.type === 'peer-unavailable') return; // 정상적인 케이스
      this.onError(err.message);
    });
  }

  /**
   * 방에 입장. PeerJS 브로커 상에서 "방 호스트" 피어에 연결을 시도.
   * roomId = SHA-256(방코드)를 방 호스트 탐색에 사용.
   *
   * 작동 방식:
   *   - 방에 입장하면 "브로드캐스트 채널 역할"을 하는 well-known 피어 ID를 계산
   *   - 해당 well-known ID로 연결 시도 → 이미 있는 피어 목록 수신
   *   - 없으면 내가 방의 첫 번째 피어(호스트) 역할 수행
   */
  async joinRoom(roomCode, roomId, roomSalt, roomName = '') {
    if (this._mode === 'manual') {
      // 수동 모드에서는 joinRoom이 의미없음 (방 개념 없음)
      this._emitRoomJoined(roomCode, roomId, roomSalt, roomName, []);
      return;
    }

    this._roomCode  = roomCode;
    this._roomId    = roomId;
    this._roomSalt  = roomSalt;
    this._roomName  = roomName;

    // 방 채널 ID: roomId 앞 36자 → PeerJS peer ID 형식 맞춤
    // 실제로는 roomId를 broadcast 채널 ID로 쓰는 "가상 피어"로 접속 시도
    const channelPeerId = 'room-' + roomId.slice(0, 27); // PeerJS ID 길이 제한 고려

    if (!this._peer) {
      this.onError('PeerJS 연결이 초기화되지 않았습니다.');
      return;
    }

    // 채널 피어에 연결 시도 (이미 방에 있는 누군가)
    this._tryConnectRoomChannel(channelPeerId, roomCode, roomId, roomSalt, roomName);
  }

  _tryConnectRoomChannel(channelPeerId, roomCode, roomId, roomSalt, roomName) {
    const conn = this._peer.connect(channelPeerId, {
      reliable: true,
      metadata: {
        type: 'room_discover',
        roomId,
        fromPeerId: this.myPeerId,
        fromPublicKey: this._myPublicKey,
        username: this._options.username || '사용자',
      }
    });

    let settled = false;

    conn.on('open', () => {
      // 연결 성공 = 방에 누군가 있음. 피어 목록 요청
      conn.send(JSON.stringify({
        type: 'room_hello',
        fromPeerId: this.myPeerId,
        publicKey: this._myPublicKey,
        username: this._options.username || '사용자',
        roomId,
      }));
    });

    conn.on('data', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      if (msg.type === 'room_peers' && !settled) {
        settled = true;
        const peers = msg.peers || [];
        this._emitRoomJoined(roomCode, roomId, roomSalt, roomName, peers);
        // 실제 WebRTC 시그널링은 p2p.js의 _initiateConnection에서 수행
      }
    });

    conn.on('error', () => {
      if (!settled) {
        settled = true;
        // 방이 비어있음 = 내가 첫 번째 피어 (호스트)
        // 호스트는 channelPeerId로 자신을 등록하려 시도하지만
        // PeerJS에서는 직접 ID 지정이 어려우므로, 방을 "열었음"으로만 처리
        this._emitRoomJoined(roomCode, roomId, roomSalt, roomName, []);
      }
    });
  }

  _emitRoomJoined(roomCode, roomId, roomSalt, roomName, peers) {
    // 기본 채널 생성 (서버 없이 로컬로)
    const defaultChannelId = roomId.slice(0, 16) + '-general';
    this.onRoomJoined({
      roomId,
      roomName: roomName || roomCode,
      roomSalt,
      persistent: false, // 서버리스 = 영구 저장 없음
      channels: [{ id: defaultChannelId, name: '일반', position: 0 }],
      peers,
    });
  }

  /**
   * 시그널링 데이터 연결 설정 (피어간 SDP/ICE 교환용)
   */
  _setupSigConn(conn) {
    conn.on('open', () => {
      const meta = conn.metadata || {};
      if (meta.type === 'room_discover') {
        // 방 탐색 요청에 피어 목록 응답
        const peers = Object.entries(this._roomPeers).map(([id, info]) => ({
          peerId: id,
          ...info,
        }));
        conn.send(JSON.stringify({ type: 'room_peers', peers }));

        // 새 피어 알림
        if (meta.fromPeerId && meta.fromPeerId !== this.myPeerId) {
          this._roomPeers[meta.fromPeerId] = {
            username: meta.username || '사용자',
            publicKey: meta.fromPublicKey || '',
          };
          this.onPeerJoined({
            peerId: meta.fromPeerId,
            username: meta.username || '사용자',
            publicKey: meta.fromPublicKey || '',
          });
        }
      }
    });

    conn.on('data', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }

      if (msg.type === 'signal') {
        // WebRTC SDP/ICE 중계
        this.onSignal({
          fromPeerId: msg.fromPeerId,
          payload: msg.payload,
        });
      } else if (msg.type === 'peer_left') {
        delete this._roomPeers[msg.peerId];
        this.onPeerLeft({ peerId: msg.peerId });
      }
    });

    const remotePeerId = conn.peer;
    this._sigConns[remotePeerId] = conn;

    conn.on('close', () => {
      delete this._sigConns[remotePeerId];
    });
  }

  // ─── SignalingClient 호환 인터페이스 ─────────────────────

  /**
   * 특정 피어에게 WebRTC 시그널(SDP/ICE) 전달
   */
  sendSignal(targetPeerId, payload) {
    if (this._mode === 'manual') {
      // 수동 모드에서는 콜백으로 전달
      this._handleManualSignal(targetPeerId, payload);
      return;
    }

    // 이미 열린 시그널링 연결 사용
    const existing = this._sigConns[targetPeerId];
    if (existing && existing.open) {
      existing.send(JSON.stringify({
        type: 'signal',
        fromPeerId: this.myPeerId,
        payload,
      }));
      return;
    }

    // 없으면 새로 연결
    if (!this._peer) return;
    const conn = this._peer.connect(targetPeerId, { reliable: true });
    conn.on('open', () => {
      this._sigConns[targetPeerId] = conn;
      conn.send(JSON.stringify({
        type: 'signal',
        fromPeerId: this.myPeerId,
        payload,
      }));
    });
    this._setupSigConn(conn);
  }

  leaveRoom() {
    if (this._roomId) {
      // 모든 시그널링 연결에 퇴장 알림
      const msg = JSON.stringify({ type: 'peer_left', peerId: this.myPeerId });
      for (const conn of Object.values(this._sigConns)) {
        if (conn.open) conn.send(msg);
      }
    }
    this._roomId   = null;
    this._roomCode = null;
    this._roomPeers = {};
  }

  switchChannel(channelId) {
    // 서버리스 모드에서는 채널 전환이 클라이언트 로컬로만 처리됨
    // (서버에 알릴 필요 없음)
  }

  storeMessage() {
    // 서버리스 모드에서는 영구 저장 불가 (no-op)
  }

  destroy() {
    this._destroyed = true;
    this.leaveRoom();
    if (this._peer) {
      this._peer.destroy();
      this._peer = null;
    }
  }

  // ─── 모드 2: 수동 교환 (완전 오프라인) ──────────────────

  /**
   * 수동 교환 모드: Offer 생성
   * friendcode.js의 buildInvitePacket을 활용
   * @returns {Promise<string>} - 상대에게 보낼 압축 패킷 (텍스트/QR로 공유)
   */
  async createManualOffer(myKeyPair, myUsername) {
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ]
    });
    this._manualPc = pc;

    const dc = pc.createDataChannel('chat', { ordered: true });
    this._manualDc = dc;

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    // ICE gathering 완료 대기
    await new Promise(resolve => {
      if (pc.iceGatheringState === 'complete') { resolve(); return; }
      pc.addEventListener('icegatheringstatechange', () => {
        if (pc.iceGatheringState === 'complete') resolve();
      });
      setTimeout(resolve, 4000); // 최대 4초 대기
    });

    const pubKeyStr = await CryptoHelper.exportPublicKey(myKeyPair.publicKey);
    const packet = await FriendCode.buildInvitePacket(
      pc.localDescription.sdp,
      myKeyPair.publicKey,
      this.myPeerId,
      myUsername
    );

    return packet; // 이걸 QR 또는 텍스트로 상대에게 전달
  }

  /**
   * 수동 교환 모드: 상대의 Offer를 받아 Answer 생성
   * @param {string} invitePacket - 상대에게 받은 텍스트/QR 내용
   * @returns {Promise<string>} - 상대에게 보낼 Answer 패킷
   */
  async answerManualOffer(invitePacket, myKeyPair, myUsername) {
    const invite = await FriendCode.parseInvitePacket(invitePacket);

    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ]
    });
    this._manualPc = pc;

    // 피어 연결 이벤트를 p2p.js 형식으로 변환
    pc.ondatachannel = (e) => {
      this._manualDc = e.channel;
      // p2p.js가 처리할 수 있도록 onSignal 모사
      this.onSignal({
        fromPeerId: invite.peerId,
        payload: {
          type: 'datachannel_ready',
          username: invite.username,
          publicKey: invite.publicKey,
          channel: e.channel,
          pc,
        }
      });
    };

    await pc.setRemoteDescription({ type: 'offer', sdp: invite.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    await new Promise(resolve => {
      if (pc.iceGatheringState === 'complete') { resolve(); return; }
      pc.addEventListener('icegatheringstatechange', () => {
        if (pc.iceGatheringState === 'complete') resolve();
      });
      setTimeout(resolve, 4000);
    });

    const answerPacket = await FriendCode.buildAnswerPacket(
      pc.localDescription.sdp,
      myKeyPair.publicKey,
      this.myPeerId,
      myUsername
    );

    // 로컬 피어 정보 등록
    this._roomPeers[invite.peerId] = {
      username: invite.username,
      publicKey: invite.publicKey,
    };

    return answerPacket;
  }

  /**
   * 수동 교환 모드: Answer 수신 후 연결 완료
   */
  async completeManualConnection(answerPacket, remotePeerId) {
    const answer = await FriendCode.parseAnswerPacket(answerPacket);
    if (this._manualPc) {
      await this._manualPc.setRemoteDescription({ type: 'answer', sdp: answer.sdp });

      this._roomPeers[answer.peerId] = {
        username: answer.username,
        publicKey: answer.publicKey,
      };

      // p2p.js에 연결 완료 알림
      this.onPeerJoined({
        peerId: answer.peerId,
        username: answer.username,
        publicKey: answer.publicKey,
      });
    }
  }

  _handleManualSignal(targetPeerId, payload) {
    // 수동 모드에서 SDP/ICE는 이미 buildInvitePacket/buildAnswerPacket에 포함
    // ICE는 trickle 없이 gathering 완료 후 일괄 전송하므로 별도 처리 불필요
  }

  get connected() {
    return this._mode === 'manual' || (this._peer && !this._peer.destroyed);
  }
}
