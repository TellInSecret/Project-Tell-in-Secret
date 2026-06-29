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

    // 호스트-기반 방 발견 상태
    this._isHost     = false;    // 내가 이 방의 호스트인지
    this._hostSlotId = null;     // 결정론적 호스트 슬롯 ID ('tic-room-...')
    this._hostConn   = null;     // (멤버일 때) 호스트로의 DataConnection

    // 수동 교환 모드용 콜백
    this.onManualInviteReady  = options.onManualInviteReady  || (() => {});
    this.onManualAnswerReady  = options.onManualAnswerReady  || (() => {});

    // 오프라인 p2p (manual) 연결 관리
    this._manualPc   = null;
    this._manualDc   = null;
  }

  // ─── 모드 1: PeerJS 브로커 기반 자동 연결 (호스트-기반 방 발견) ──
  //
  // 동작 원리:
  //   각 방(roomId)마다 결정론적 "호스트 슬롯 ID" = 'room-' + roomId 앞부분.
  //   방에 처음 들어온 피어가 그 ID로 PeerJS에 등록 → 호스트가 된다.
  //   이미 호스트가 있으면 ID 등록이 'unavailable-id'로 실패 →
  //   나는 랜덤 ID로 등록하고 호스트에게 접속한다.
  //   호스트는 모든 멤버 목록을 관리하고, 새 멤버가 오면 기존 멤버 목록을
  //   알려준다. 그 목록을 받은 멤버는 p2p.js가 풀 메시 WebRTC 연결을 시작한다.
  //   WebRTC 시그널(offer/answer/ice)은 호스트를 라우터로 거쳐 대상 피어에 전달.

  /**
   * PeerJS 라이브러리 가용성만 확인. 실제 Peer 등록은 joinRoom에서.
   * @param {string} peerId - 내 고유 ID (UUID) — 일반 멤버일 때 사용
   * @param {string} publicKeyBase64 - 내 공개키
   */
  connect(peerId, publicKeyBase64) {
    if (this._destroyed) return;
    this.myPeerId   = peerId;
    this._myPublicKey = publicKeyBase64;

    if (typeof Peer === 'undefined') {
      console.warn('[Signaling] PeerJS 미로드 → 수동 교환 모드로 폴백');
      this._mode = 'manual';
    } else {
      this._mode = 'peerjs';
    }
    // 실제 연결은 joinRoom에서 수행. 여기서는 "준비됨"만 알림.
    this.onConnected(this.myPeerId);
  }

  /**
   * 방 입장. 호스트 슬롯 등록을 시도하고, 실패하면 호스트에 접속한다.
   */
  async joinRoom(roomCode, roomId, roomSalt, roomName = '') {
    this._roomCode = roomCode;
    this._roomId   = roomId;
    this._roomSalt = roomSalt;
    this._roomName = roomName;
    this._isHost   = false;
    this._hostConn = null;
    this._roomPeers = {};

    if (this._mode === 'manual') {
      // 수동 모드: 방 개념 없이 즉시 입장 처리 (피어 0명, 수동 교환으로 추가)
      this._emitRoomJoined(roomCode, roomId, roomSalt, roomName, []);
      return;
    }

    // PeerJS ID 규칙(영숫자/하이픈)에 맞춘 결정론적 호스트 슬롯 ID
    this._hostSlotId = 'tic-room-' + roomId.slice(0, 32);

    // 1) 먼저 호스트가 되어 본다 (호스트 슬롯 ID로 PeerJS 등록 시도)
    this._tryBecomeHost();
  }

  // ── 호스트 등록 시도 ──────────────────────────────────────
  _tryBecomeHost() {
    const hostPeer = new Peer(this._hostSlotId, {
      host: PEERJS_HOST, port: PEERJS_PORT, path: PEERJS_PATH, secure: true,
    });

    let settled = false;

    hostPeer.on('open', (id) => {
      // 호스트 슬롯 선점 성공 → 내가 이 방의 호스트
      if (settled) return;
      settled = true;
      this._isHost = true;
      this._peer = hostPeer;
      // 호스트 자신도 멤버 목록에 포함
      this._roomPeers[this.myPeerId] = {
        username: this._options.username || '사용자',
        publicKey: this._myPublicKey,
      };
      this._wireHostPeer(hostPeer);
      console.log('[Signaling] 이 피어가 방 호스트가 되었습니다:', id);
      // 호스트는 기존 멤버가 없으므로 빈 목록으로 입장 완료
      this._emitRoomJoined(this._roomCode, this._roomId, this._roomSalt, this._roomName, []);
    });

    hostPeer.on('error', (err) => {
      if (settled) return;
      if (err && (err.type === 'unavailable-id' || /taken|unavailable/i.test(err.message || ''))) {
        // 이미 호스트가 존재 → 나는 일반 멤버로 합류
        settled = true;
        try { hostPeer.destroy(); } catch (_) {}
        this._joinAsMember();
      } else {
        console.error('[Signaling][host]', err);
        this.onError(err.message || '호스트 등록 오류');
      }
    });
  }

  // ── 호스트: 들어오는 연결 처리 ────────────────────────────
  _wireHostPeer(hostPeer) {
    hostPeer.on('connection', (conn) => this._setupHostSideConn(conn));
    hostPeer.on('disconnected', () => {
      this.onDisconnected();
      if (!this._destroyed) { try { hostPeer.reconnect(); } catch (_) {} }
    });
  }

  _setupHostSideConn(conn) {
    conn.on('open', () => {
      const remoteId = conn.peer;
      this._sigConns[remoteId] = conn;
    });

    conn.on('data', (raw) => {
      let msg; try { msg = JSON.parse(raw); } catch { return; }
      this._hostHandleMessage(conn, msg);
    });

    conn.on('close', () => {
      const remoteId = conn.peer;
      delete this._sigConns[remoteId];
      if (this._roomPeers[remoteId]) {
        delete this._roomPeers[remoteId];
        // 다른 멤버들에게 퇴장 전파
        this._hostBroadcast({ type: 'peer_left', peerId: remoteId });
        this.onPeerLeft({ peerId: remoteId });
      }
    });
  }

  // 호스트가 받은 메시지 처리: 합류 등록 / 시그널 라우팅
  _hostHandleMessage(conn, msg) {
    if (msg.type === 'hello') {
      const id = msg.fromPeerId;
      // 신규 멤버에게 "현재 멤버 목록"(나 + 기존 멤버) 전달
      const peers = Object.entries(this._roomPeers).map(([pid, info]) => ({ peerId: pid, ...info }));
      this._send(conn, { type: 'welcome', peers });

      // 멤버 등록 후 기존 멤버들에게 새 멤버 알림
      this._roomPeers[id] = { username: msg.username || '사용자', publicKey: msg.publicKey || '' };
      this._hostBroadcast({
        type: 'peer_joined', peerId: id, username: msg.username || '사용자', publicKey: msg.publicKey || '',
      }, id);
      // 호스트 자신도 새 멤버를 인지 (p2p가 연결 시도하도록)
      this.onPeerJoined({ peerId: id, username: msg.username || '사용자', publicKey: msg.publicKey || '' });
      return;
    }

    if (msg.type === 'signal') {
      // 멤버 → 멤버 시그널 라우팅 (호스트가 중계)
      this._routeSignal(msg.targetPeerId, {
        type: 'signal', fromPeerId: msg.fromPeerId, payload: msg.payload,
      });
      return;
    }

    if (msg.type === 'peer_left') {
      const id = msg.fromPeerId;
      if (this._roomPeers[id]) delete this._roomPeers[id];
      delete this._sigConns[id];
      this._hostBroadcast({ type: 'peer_left', peerId: id }, id);
      this.onPeerLeft({ peerId: id });
    }
  }

  // 호스트: 특정 멤버에게 전달 (대상이 호스트면 자기 콜백 호출)
  _routeSignal(targetPeerId, obj) {
    if (targetPeerId === this.myPeerId) {
      this.onSignal({ fromPeerId: obj.fromPeerId, payload: obj.payload });
      return;
    }
    const conn = this._sigConns[targetPeerId];
    if (conn && conn.open) this._send(conn, obj);
  }

  // 호스트: 모든 멤버에게 브로드캐스트 (exceptId 제외)
  _hostBroadcast(obj, exceptId = null) {
    for (const [pid, conn] of Object.entries(this._sigConns)) {
      if (pid === exceptId) continue;
      if (conn && conn.open) this._send(conn, obj);
    }
  }

  // ── 일반 멤버로 호스트에 합류 ─────────────────────────────
  _joinAsMember() {
    const memberPeer = new Peer(this.myPeerId, {
      host: PEERJS_HOST, port: PEERJS_PORT, path: PEERJS_PATH, secure: true,
    });
    this._peer = memberPeer;

    memberPeer.on('open', () => {
      // 호스트에 시그널링 연결
      const conn = memberPeer.connect(this._hostSlotId, { reliable: true });
      this._hostConn = conn;

      conn.on('open', () => {
        this._sigConns[this._hostSlotId] = conn;
        this._send(conn, {
          type: 'hello',
          fromPeerId: this.myPeerId,
          username: this._options.username || '사용자',
          publicKey: this._myPublicKey,
        });
      });

      conn.on('data', (raw) => {
        let msg; try { msg = JSON.parse(raw); } catch { return; }
        this._memberHandleMessage(msg);
      });

      conn.on('close', () => {
        delete this._sigConns[this._hostSlotId];
        this.onDisconnected();
        // 호스트 다운 → 잠시 후 재입장 시도(누군가 새 호스트가 됨)
        if (!this._destroyed) {
          setTimeout(() => { if (!this._destroyed) this.joinRoom(this._roomCode, this._roomId, this._roomSalt, this._roomName); }, 1500);
        }
      });

      conn.on('error', (e) => console.warn('[Signaling][member→host]', e?.message || e));
    });

    // 다른 멤버가 나에게 직접 연결해 올 수도 있음 (시그널 직접 경로)
    memberPeer.on('connection', (c) => this._setupPeerToPeerConn(c));

    memberPeer.on('disconnected', () => {
      this.onDisconnected();
      if (!this._destroyed) { try { memberPeer.reconnect(); } catch (_) {} }
    });

    memberPeer.on('error', (err) => {
      if (err && err.type === 'peer-unavailable') {
        // 호스트가 사라짐 → 내가 호스트가 되어 본다
        if (!this._destroyed) this._tryBecomeHost();
        return;
      }
      console.error('[Signaling][member]', err);
    });
  }

  _memberHandleMessage(msg) {
    if (msg.type === 'welcome') {
      // 호스트가 준 멤버 목록으로 입장 완료 → p2p가 풀 메시 연결 시작
      const peers = msg.peers || [];
      this._emitRoomJoined(this._roomCode, this._roomId, this._roomSalt, this._roomName, peers);
      return;
    }
    if (msg.type === 'peer_joined') {
      this._roomPeers[msg.peerId] = { username: msg.username, publicKey: msg.publicKey };
      this.onPeerJoined(msg);
      return;
    }
    if (msg.type === 'peer_left') {
      delete this._roomPeers[msg.peerId];
      this.onPeerLeft({ peerId: msg.peerId });
      return;
    }
    if (msg.type === 'signal') {
      this.onSignal({ fromPeerId: msg.fromPeerId, payload: msg.payload });
      return;
    }
  }

  // 멤버 간 직접 연결(호스트 경유 없이 받은 연결) 처리
  _setupPeerToPeerConn(conn) {
    conn.on('open', () => { this._sigConns[conn.peer] = conn; });
    conn.on('data', (raw) => {
      let msg; try { msg = JSON.parse(raw); } catch { return; }
      if (msg.type === 'signal') this.onSignal({ fromPeerId: msg.fromPeerId, payload: msg.payload });
    });
    conn.on('close', () => { delete this._sigConns[conn.peer]; });
  }

  _emitRoomJoined(roomCode, roomId, roomSalt, roomName, peers) {
    const defaultChannelId = CryptoHelper.defaultChannelId(roomId);
    this.onRoomJoined({
      roomId,
      roomName: roomName || roomCode,
      roomSalt,
      persistent: false,
      channels: [{ id: defaultChannelId, name: '일반', position: 0 }],
      peers,
    });
  }

  _send(conn, obj) {
    try { conn.send(JSON.stringify(obj)); } catch (_) {}
  }

  // ─── SignalingClient 호환 인터페이스 ─────────────────────

  /**
   * 특정 피어에게 WebRTC 시그널(SDP/ICE) 전달.
   * 호스트면 직접 라우팅, 멤버면 호스트를 통해 중계.
   */
  sendSignal(targetPeerId, payload) {
    if (this._mode === 'manual') { this._handleManualSignal(targetPeerId, payload); return; }

    if (this._isHost) {
      this._routeSignal(targetPeerId, { type: 'signal', fromPeerId: this.myPeerId, payload });
      return;
    }
    // 멤버: 호스트에게 라우팅 요청
    const hostConn = this._sigConns[this._hostSlotId];
    if (hostConn && hostConn.open) {
      this._send(hostConn, { type: 'signal', fromPeerId: this.myPeerId, targetPeerId, payload });
    }
  }

  leaveRoom() {
    if (this._mode !== 'manual') {
      const notice = { type: 'peer_left', fromPeerId: this.myPeerId, peerId: this.myPeerId };
      if (this._isHost) {
        this._hostBroadcast({ type: 'peer_left', peerId: this.myPeerId });
      } else {
        const hostConn = this._sigConns[this._hostSlotId];
        if (hostConn && hostConn.open) this._send(hostConn, notice);
      }
    }
    this._roomId   = null;
    this._roomCode = null;
    this._roomPeers = {};
    this._isHost   = false;
    // 방을 나가면 Peer 인스턴스도 정리(다음 방에서 새 ID/슬롯으로 등록)
    if (this._peer) { try { this._peer.destroy(); } catch (_) {} this._peer = null; }
    this._sigConns = {};
  }

  switchChannel(channelId) {
    // 서버리스: 채널 전환은 클라이언트 로컬 처리 (no-op)
  }

  storeMessage() {
    // 서버리스: 영구 저장 없음 (no-op)
  }

  destroy() {
    this._destroyed = true;
    this.leaveRoom();
    if (this._peer) {
      try { this._peer.destroy(); } catch (_) {}
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
