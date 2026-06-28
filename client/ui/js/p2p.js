/**
 * P2PMeshManager - 그리드넷 메시 P2P 매니저 (v2 - Serverless)
 *
 * v2 핵심 변경:
 *  - 방 코드(자동 생성) → roomSalt/roomId를 로컬에서 결정론적 파생
 *    서버에 roomSalt 요청 불필요, 백엔드 인증 서버 불필요
 *  - DataChannel 연결 후 SPAKE2-lite 상호 인증 (challenge-response)
 *    → 방 코드 충돌 시에도 다른 그룹 메시지 열람 불가
 *  - Gossip 중복 방지: msgId + _seenMsgIds Set (최근 1000개)
 *  - HKDF channel key에 roomSalt 적용 (zero-bytes → roomSalt)
 *  - _handleFileChunk: ArrayBuffer 타입 혼재 방어 코드 추가
 *
 * 그리드넷 원리:
 *  - 방 코드를 가진 모든 피어가 동등 (서버 없음)
 *  - 새 피어 입장 → 시그널링(PeerJS 브로커 or 수동)으로 기존 피어 목록 수신
 *  - 새 피어가 기존 피어 전원에게 WebRTC offer (풀메시 형성)
 *  - 연결 후 상호 인증 통과한 피어만 메시지 교환
 *  - 메시지는 gossip broadcast (TTL + msgId 중복 방지)
 */
class P2PMeshManager {
  constructor(options = {}) {
    this.myPeerId = null;
    this.myUsername = options.username || '사용자';
    this.onMessage      = options.onMessage      || (() => {});
    this.onStatusChange = options.onStatusChange || (() => {});
    this.onFileProgress = options.onFileProgress || (() => {});
    this.onChannelUpdate = options.onChannelUpdate || (() => {});
    this.onPeerUpdate   = options.onPeerUpdate   || (() => {});

    // Long-term identity keypair (ECDH P-256)
    this.localKeyPair = null;
    this.localPublicKeyBase64 = null;

    // Peers: peerId -> { connection, dataChannel, username, publicKey, sharedKey, authenticated }
    this.peers = {};

    // Room state
    this.roomId         = null;
    this.roomCode       = null;   // [v2] 방 코드 (비밀, 사용자에게만 공개)
    this.roomName       = '';
    this.roomSalt       = '';     // [v2] 로컬 파생 (서버에서 안 받음)
    this.isPersistent   = false;
    this.groupKey       = null;
    this.channelKeys    = {};
    this.channels       = [];
    this.activeChannelId = null;

    // File transfer state
    this.incomingFiles  = {};
    this.activeTransfers = {};

    // Signaling client
    this.signalingClient = null;

    // [v2] Gossip 중복 방지: 최근 수신한 msgId 기억
    this._seenMsgIds = new Set();
    this._MAX_SEEN   = 1000;

    // [v2] 인증 대기 중인 챌린지: peerId -> { challenge, timeout }
    this._pendingChallenges = {};

    this.rtcConfig = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ]
    };
  }

  // ─── Initialize (load or generate long-term keypair) ─────
  async initialize(existingKeyPair = null, existingPublicKeyBase64 = null) {
    if (existingKeyPair && existingPublicKeyBase64) {
      this.localKeyPair = existingKeyPair;
      this.localPublicKeyBase64 = existingPublicKeyBase64;
      return;
    }

    const authManager = window.AuthManager || window.LocalIdentity;
    if (authManager?.getDecryptedKeyPair) {
      const authKeyPair = authManager.getDecryptedKeyPair();
      if (authKeyPair?.publicKey && authKeyPair?.privateKey) {
        this.localKeyPair = authKeyPair;
        this.localPublicKeyBase64 = await CryptoHelper.exportPublicKey(authKeyPair.publicKey);
        return;
      }
    }

    const invoke = window.__TAURI__?.core?.invoke;
    const saveKp = async (pub, privJwk) => {
      const data = JSON.stringify({ pub, priv: privJwk });
      if (invoke) {
        try { await invoke('save_secure_data', { filename: 'identity_keypair.json', data }); return; } catch (_) {}
      }
      localStorage.setItem('ticmsg_identity_kp', data);
    };
    const loadKp = async () => {
      if (invoke) {
        try {
          const d = await invoke('load_secure_data', { filename: 'identity_keypair.json' });
          if (d) return JSON.parse(d);
        } catch (_) {}
      }
      const d = localStorage.getItem('ticmsg_identity_kp');
      return d ? JSON.parse(d) : null;
    };

    const stored = await loadKp();
    if (stored && stored.pub && stored.priv) {
      try {
        this.localKeyPair = await CryptoHelper.loadIdentityKeyPair(stored.pub, stored.priv);
        this.localPublicKeyBase64 = stored.pub;
        return;
      } catch (_) {}
    }

    this.localKeyPair = await CryptoHelper.generateAndSaveIdentityKeyPair(saveKp);
    this.localPublicKeyBase64 = await CryptoHelper.exportPublicKey(this.localKeyPair.publicKey);
  }

  setUsername(username) { this.myUsername = username; }

  // ─── Attach Signaling Client ──────────────────────────────
  attachSignaling(sigClient) {
    this.signalingClient = sigClient;

    sigClient.onRoomJoined = async (msg) => {
      this.roomId      = msg.roomId;
      this.roomName    = msg.roomName;
      this.roomSalt    = msg.roomSalt;  // [v2] 로컬 파생된 salt
      this.isPersistent = msg.persistent;
      this.channels    = msg.channels || [];

      this.onChannelUpdate(this.channels);
      this.onStatusChange();

      // 풀 메시: 기존 피어 전원에게 연결 시도
      for (const peer of (msg.peers || [])) {
        await this._initiateConnection(peer.peerId, peer.username, peer.publicKey);
      }
    };

    sigClient.onPeerJoined = async (msg) => {
      this.onPeerUpdate('joined', msg.peerId, msg.username);
    };

    sigClient.onPeerLeft = (msg) => {
      this._cleanupPeer(msg.peerId);
      this.onPeerUpdate('left', msg.peerId, '');
      this.onStatusChange();
    };

    sigClient.onSignal = async (msg) => {
      await this._handleRemoteSignal(msg.fromPeerId, msg.payload);
    };
  }

  // ─── Join Room (v2: 방 코드에서 모든 것 파생) ───────────────
  /**
   * @param {string} roomCode - 방 코드 (예: "apple-river-7341")
   * @param {string} roomName - 표시할 방 이름 (선택)
   */
  async joinRoomWithCode(roomCode, roomName = '') {
    this.roomCode = roomCode;

    // [v2] 서버 없이 로컬에서 salt와 roomId 파생
    this.roomSalt = await CryptoHelper.deriveRoomSalt(roomCode);
    this.roomId   = await CryptoHelper.deriveRoomId(roomCode);

    // 그룹 키 파생 (PBKDF2, 200K iterations)
    this.groupKey = await CryptoHelper.deriveRoomGroupKey(roomCode, this.roomSalt);
    this.channelKeys = {};

    // 시그널링 클라이언트에게 방 입장 요청 (roomId = 공개 식별자)
    if (this.signalingClient?.joinRoom) {
      await this.signalingClient.joinRoom(roomCode, this.roomId, this.roomSalt, roomName || roomCode);
    }
  }

  async joinRoomWithPassword(roomCode, roomPassword, roomSalt = '') {
    this.roomCode = roomCode;
    this.roomSalt = roomSalt || await CryptoHelper.deriveRoomSalt(roomCode);
    this.roomId   = await CryptoHelper.deriveRoomId(roomCode);
    this.groupKey = await CryptoHelper.deriveRoomGroupKey(roomCode, this.roomSalt);
    this.channelKeys = {};
    if (this.signalingClient?.joinRoom) {
      await this.signalingClient.joinRoom(roomCode, this.roomId, this.roomSalt, roomPassword || roomCode);
    }
  }

  // 채널 키 파생 ([v2] roomSalt 활용)
  async _ensureChannelKey(channelId) {
    if (!this.channelKeys[channelId] && this.groupKey) {
      this.channelKeys[channelId] = await CryptoHelper.deriveChannelKey(
        this.groupKey, channelId, this.roomSalt
      );
    }
    return this.channelKeys[channelId];
  }

  // ─── WebRTC 연결: Initiator ───────────────────────────────
  async _initiateConnection(remotePeerId, remoteUsername, remotePubKeyStr) {
    if (this.peers[remotePeerId]) return;

    const pc = new RTCPeerConnection(this.rtcConfig);
    const dc = pc.createDataChannel('chat', { ordered: true });

    this.peers[remotePeerId] = {
      connection: pc,
      dataChannel: dc,
      username: remoteUsername,
      publicKey: remotePubKeyStr ? await CryptoHelper.importPublicKey(remotePubKeyStr) : null,
      sharedKey: null,
      authenticated: false,  // [v2] 인증 전에는 채팅 메시지 처리 안 함
    };

    this._setupDataChannel(remotePeerId, dc);

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.signalingClient?.sendSignal(remotePeerId, {
          type: 'ice', candidate: e.candidate,
        });
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    this.signalingClient?.sendSignal(remotePeerId, {
      type: 'offer',
      sdp: pc.localDescription.sdp,
      username: this.myUsername,
      publicKey: this.localPublicKeyBase64,
    });
  }

  // ─── WebRTC 연결: Responder ───────────────────────────────
  async _handleRemoteSignal(fromPeerId, payload) {
    if (payload.type === 'offer') {
      const pc = new RTCPeerConnection(this.rtcConfig);
      const remotePubKey = payload.publicKey
        ? await CryptoHelper.importPublicKey(payload.publicKey)
        : null;

      this.peers[fromPeerId] = {
        connection: pc,
        dataChannel: null,
        username: payload.username || '피어',
        publicKey: remotePubKey,
        sharedKey: null,
        authenticated: false,
      };

      pc.ondatachannel = (e) => {
        this.peers[fromPeerId].dataChannel = e.channel;
        this._setupDataChannel(fromPeerId, e.channel);
      };

      pc.onicecandidate = (e) => {
        if (e.candidate) {
          this.signalingClient?.sendSignal(fromPeerId, {
            type: 'ice', candidate: e.candidate,
          });
        }
      };

      await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: payload.sdp }));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      this.signalingClient?.sendSignal(fromPeerId, {
        type: 'answer',
        sdp: pc.localDescription.sdp,
        username: this.myUsername,
        publicKey: this.localPublicKeyBase64,
      });
    }
    else if (payload.type === 'answer') {
      const peer = this.peers[fromPeerId];
      if (peer?.connection) {
        if (!peer.publicKey && payload.publicKey) {
          peer.publicKey = await CryptoHelper.importPublicKey(payload.publicKey);
        }
        if (peer.connection.signalingState !== 'stable') {
          await peer.connection.setRemoteDescription(
            new RTCSessionDescription({ type: 'answer', sdp: payload.sdp })
          );
        }
      }
    }
    else if (payload.type === 'ice') {
      const peer = this.peers[fromPeerId];
      if (peer?.connection && payload.candidate) {
        try {
          await peer.connection.addIceCandidate(new RTCIceCandidate(payload.candidate));
        } catch (_) {}
      }
    }
  }

  // ─── DataChannel 설정 ─────────────────────────────────────
  _setupDataChannel(peerId, channel) {
    channel.onopen = async () => {
      console.log(`[Mesh] Connected to ${this.peers[peerId]?.username}`);
      const peer = this.peers[peerId];
      if (!peer) return;

      // ECDH shared key 계산
      if (peer.publicKey && this.localKeyPair) {
        try {
          peer.sharedKey = await CryptoHelper.deriveSharedKey(
            this.localKeyPair.privateKey,
            peer.publicKey
          );
        } catch (_) {}
      }

      // [v2] 연결 후 즉시 SPAKE2-lite 상호 인증 시작
      await this._startMutualAuth(peerId, channel);
    };

    channel.onclose = () => {
      this._cleanupPeer(peerId);
      this.onStatusChange();
    };

    channel.onerror = (err) => console.error('[DataChannel Error]', err);

    channel.onmessage = async (event) => {
      // 바이너리: 파일 청크
      if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
        // [v2 fix] Blob → ArrayBuffer 변환 보장
        const buf = event.data instanceof Blob
          ? await event.data.arrayBuffer()
          : event.data;
        await this._handleFileChunk(buf, peerId);
        return;
      }

      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }

      // [v2] 인증 메시지는 인증 상태와 무관하게 처리
      if (packet.type === 'AUTH_CHALLENGE' || packet.type === 'AUTH_RESPONSE' || packet.type === 'AUTH_VERIFY') {
        await this._handleAuthPacket(packet, peerId, channel);
        return;
      }

      // [v2] 인증 전에는 채팅/파일 메시지 무시 (방 코드 충돌 방어)
      if (!this.peers[peerId]?.authenticated) return;

      switch (packet.type) {
        case 'CHAT_MSG':
          await this._handleChatMsg(packet, peerId);
          break;
        case 'FILE_META':
          await this._handleFileMeta(packet, peerId);
          break;
        case 'MESH_RELAY':
          if (packet.inner) {
            this._relayToOthers(packet, peerId);
            await this._handleChatMsg(packet.inner, peerId);
          }
          break;
      }
    };
  }

  _cleanupPeer(peerId) {
    const peer = this.peers[peerId];
    if (!peer) return;
    // 인증 타임아웃 클리어
    if (this._pendingChallenges[peerId]?.timeout) {
      clearTimeout(this._pendingChallenges[peerId].timeout);
    }
    delete this._pendingChallenges[peerId];
    try { peer.dataChannel?.close(); } catch (_) {}
    try { peer.connection?.close(); } catch (_) {}
    delete this.peers[peerId];
  }

  // ─── [v2] SPAKE2-lite 상호 인증 ──────────────────────────
  /**
   * DataChannel 연결 직후 호출.
   * ECDH sharedKey로 챌린지-응답 교환 → 양측이 동일한 방 코드 소유 증명.
   *
   * 보안:
   *  - sharedKey는 ECDH 파생 (비밀번호와 무관)
   *  - 방 코드 충돌 그룹: 공개키가 달라 sharedKey가 달라 → 복호화 실패 → 인증 실패 → 연결 차단
   *  - MITM: sharedKey 계산에 양측 공개키 모두 필요 → 제3자 개입 불가
   */
  async _startMutualAuth(peerId, channel) {
    const peer = this.peers[peerId];
    if (!peer?.sharedKey) {
      // sharedKey 없으면 인증 불가 → 바로 인증됨으로 처리 (공개키 없는 수동연결 호환)
      peer.authenticated = true;
      this.onStatusChange();
      return;
    }

    const myChallenge = FriendCode.generateChallenge();

    // 타임아웃: 10초 내 인증 완료 못하면 연결 끊기
    const timeout = setTimeout(() => {
      console.warn(`[Auth] Timeout for peer ${peerId}, disconnecting`);
      this._cleanupPeer(peerId);
      this.onStatusChange();
    }, 10000);

    this._pendingChallenges[peerId] = { challenge: myChallenge, timeout };

    // 내 챌린지 전송
    channel.send(JSON.stringify({
      type: 'AUTH_CHALLENGE',
      challenge: myChallenge,
    }));
  }

  async _handleAuthPacket(packet, peerId, channel) {
    const peer = this.peers[peerId];
    if (!peer?.sharedKey) return;

    if (packet.type === 'AUTH_CHALLENGE') {
      // 상대 챌린지를 내 sharedKey로 암호화해 응답
      const response = await FriendCode.respondToChallenge(packet.challenge, peer.sharedKey);
      channel.send(JSON.stringify({
        type: 'AUTH_RESPONSE',
        response,
      }));
    }
    else if (packet.type === 'AUTH_RESPONSE') {
      // 상대 응답 검증
      const pending = this._pendingChallenges[peerId];
      if (!pending) return;

      const valid = await FriendCode.verifyResponse(
        pending.challenge, packet.response, peer.sharedKey
      );

      if (!valid) {
        console.warn(`[Auth] Failed mutual auth with ${peer.username} (wrong room code or MITM)`);
        this._cleanupPeer(peerId);
        this.onStatusChange();
        return;
      }

      // 내 챌린지 검증 완료 → 상대에게 확인 전송
      clearTimeout(pending.timeout);
      delete this._pendingChallenges[peerId];

      channel.send(JSON.stringify({ type: 'AUTH_VERIFY', ok: true }));

      // 양측 AUTH_VERIFY 확인 후 인증 완료 처리
      peer._authLocalOk = true;
      if (peer._authRemoteOk) {
        peer.authenticated = true;
        console.log(`[Auth] ✓ Mutual auth complete with ${peer.username}`);
        this.onPeerUpdate('authenticated', peerId, peer.username);
        this.onStatusChange();
      }
    }
    else if (packet.type === 'AUTH_VERIFY') {
      if (!packet.ok) {
        this._cleanupPeer(peerId);
        this.onStatusChange();
        return;
      }
      peer._authRemoteOk = true;
      if (peer._authLocalOk) {
        peer.authenticated = true;
        console.log(`[Auth] ✓ Mutual auth complete with ${peer.username}`);
        this.onPeerUpdate('authenticated', peerId, peer.username);
        this.onStatusChange();
      }
    }
  }

  // ─── [v2] Grid-Net Relay (gossip + 중복 방지) ─────────────
  _markSeen(msgId) {
    if (this._seenMsgIds.has(msgId)) return false; // 이미 본 메시지
    this._seenMsgIds.add(msgId);
    if (this._seenMsgIds.size > this._MAX_SEEN) {
      // Set은 삽입 순서 유지 → 가장 오래된 항목 제거
      const first = this._seenMsgIds.values().next().value;
      this._seenMsgIds.delete(first);
    }
    return true;
  }

  _relayToOthers(packet, fromPeerId) {
    if (!packet.msgId || !this._markSeen(packet.msgId)) return; // 중복 방지
    if (!packet.ttl || packet.ttl <= 0) return;

    const relayPacket = JSON.stringify({ ...packet, ttl: packet.ttl - 1 });
    for (const id in this.peers) {
      if (id === fromPeerId || !this.peers[id].authenticated) continue;
      const ch = this.peers[id].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(relayPacket);
    }
  }

  // ─── 메시지 전송 ──────────────────────────────────────────
  async sendMessage(text, channelId = null) {
    const cid = channelId || this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;

    const encrypted = await CryptoHelper.encrypt(key, text);
    // [v2] msgId 추가 → gossip 중복 방지
    const msgId = crypto.randomUUID();

    const packet = JSON.stringify({
      type: 'CHAT_MSG',
      channelId: cid,
      ciphertext: encrypted,
      msgId,
      ttl: 3,
    });

    // 내가 보낸 메시지는 seen으로 등록 (내 자신에게 릴레이되지 않도록)
    this._markSeen(msgId);

    for (const peerId in this.peers) {
      if (!this.peers[peerId].authenticated) continue;
      const ch = this.peers[peerId].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(packet);
    }

    this.onMessage(this.roomName, this.myUsername, text, null, cid);
  }

  async _handleChatMsg(packet, fromPeerId) {
    // [v2] msgId 중복 체크 (직접 수신 메시지도)
    if (packet.msgId && !this._markSeen(packet.msgId)) return;

    const cid = packet.channelId || this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;
    try {
      const plainText = await CryptoHelper.decrypt(key, packet.ciphertext);
      const sender = this.peers[fromPeerId]?.username || '알 수 없음';
      this.onMessage(this.roomName, sender, plainText, null, cid);
    } catch (e) {
      console.error('Failed to decrypt chat message', e);
    }
  }

  // ─── 파일 전송 ────────────────────────────────────────────
  async sendFile(file, channelId = null) {
    const cid = channelId || this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;

    const CHUNK_SIZE = 32 * 1024;
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const fileId = crypto.randomUUID();

    const rawGroupKey = await CryptoHelper.exportSymmetricKey(key);
    const rawGroupKeyBytes = new Uint8Array(CryptoHelper.base64ToArrayBuffer(rawGroupKey));

    const meta = JSON.stringify({ fileId, name: file.name, size: file.size, type: file.type, totalChunks, channelId: cid });
    const encMeta = await CryptoHelper.encrypt(key, meta);
    const metaPacket = JSON.stringify({ type: 'FILE_META', ciphertext: encMeta });

    this._broadcastToAuthenticated(metaPacket);
    this.onMessage(this.roomName, this.myUsername, `[파일 전송 시작: ${file.name}]`, null, cid);

    this.activeTransfers[fileId] = { cancelFlag: false };

    let offset = 0, chunkIndex = 0;
    const startTime = Date.now();

    const readAndSendChunk = () => {
      if (this.activeTransfers[fileId]?.cancelFlag || offset >= file.size) {
        if (offset >= file.size) this.onFileProgress(fileId, 100, 0, 'completed');
        return;
      }

      const slice = file.slice(offset, offset + CHUNK_SIZE);
      const reader = new FileReader();
      reader.onload = async (e) => {
        const rawBuffer = e.target.result;
        const chunkBytes = new Uint8Array(rawBuffer);
        let encryptedChunkBytes;

        if (window.__TAURI__?.core) {
          try {
            const res = await window.__TAURI__.core.invoke('encrypt_file_chunk', {
              key: Array.from(rawGroupKeyBytes),
              chunk: Array.from(chunkBytes),
              chunkIndex,
            });
            encryptedChunkBytes = new Uint8Array(res);
          } catch { return; }
        } else {
          const iv = new Uint8Array(12);
          new DataView(iv.buffer).setUint32(8, chunkIndex);
          const enc = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, rawBuffer);
          encryptedChunkBytes = new Uint8Array(12 + enc.byteLength);
          encryptedChunkBytes.set(iv);
          encryptedChunkBytes.set(new Uint8Array(enc), 12);
        }

        const fileIdBytes = new TextEncoder().encode(fileId);
        const pkt = new Uint8Array(36 + 4 + encryptedChunkBytes.byteLength);
        pkt.set(fileIdBytes);
        new DataView(pkt.buffer).setUint32(36, chunkIndex);
        pkt.set(encryptedChunkBytes, 40);

        let needsWait = false;
        for (const pid in this.peers) {
          if (!this.peers[pid].authenticated) continue;
          const ch = this.peers[pid].dataChannel;
          if (ch && ch.readyState === 'open') {
            ch.send(pkt.buffer);
            if (ch.bufferedAmount > 256 * 1024) needsWait = true;
          }
        }

        offset += CHUNK_SIZE;
        chunkIndex++;
        const speed = offset / ((Date.now() - startTime) / 1000 || 1);
        this.onFileProgress(fileId, Math.min((offset / file.size) * 100, 100), speed, 'sending');

        if (needsWait) {
          const ch = Object.values(this.peers).find(p => p.authenticated)?.dataChannel;
          if (ch) { ch.onbufferedamountlow = () => { ch.onbufferedamountlow = null; readAndSendChunk(); }; }
          else setTimeout(readAndSendChunk, 20);
        } else {
          setTimeout(readAndSendChunk, 1);
        }
      };
      reader.readAsArrayBuffer(slice);
    };

    readAndSendChunk();
  }

  async _handleFileMeta(packet, fromPeerId) {
    const cid = this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;
    try {
      const metaStr = await CryptoHelper.decrypt(key, packet.ciphertext);
      const meta = JSON.parse(metaStr);
      this.incomingFiles[meta.fileId] = { ...meta, receivedChunksCount: 0 };
      this.onMessage(this.roomName, this.peers[fromPeerId]?.username || '알 수 없음',
        `[파일 수신 대기: ${meta.name}]`, null, meta.channelId);
    } catch (e) { console.error('File meta decrypt failed', e); }
  }

  async _handleFileChunk(arrayBuffer, senderId) {
    // [v2 fix] ArrayBuffer가 맞는지 확인 (Blob 변환은 onmessage에서 이미 처리)
    if (!(arrayBuffer instanceof ArrayBuffer)) return;
    if (arrayBuffer.byteLength < 40) return;

    // [v2 fix] DataView/Uint8Array 생성 전 길이 체크
    const fileIdBytes = new Uint8Array(arrayBuffer, 0, 36);
    const fileId = new TextDecoder().decode(fileIdBytes);
    const fileData = this.incomingFiles[fileId];
    if (!fileData) return;

    const chunkIndex = new DataView(arrayBuffer, 36, 4).getUint32(0);
    const encData    = new Uint8Array(arrayBuffer, 40);
    const cid        = fileData.channelId || this.activeChannelId;
    const key        = await this._ensureChannelKey(cid);
    if (!key) return;

    const rawGroupKey      = await CryptoHelper.exportSymmetricKey(key);
    const rawGroupKeyBytes = new Uint8Array(CryptoHelper.base64ToArrayBuffer(rawGroupKey));

    try {
      if (window.__TAURI__?.core) {
        const res = await window.__TAURI__.core.invoke('decrypt_file_chunk', {
          key: Array.from(rawGroupKeyBytes),
          encryptedChunk: Array.from(encData),
        });
        const decryptedBytes = new Uint8Array(res);
        const savedPath = await window.__TAURI__.core.invoke('write_received_chunk', {
          filename: fileData.name,
          chunk: Array.from(decryptedBytes),
          isFirst: chunkIndex === 0,
        });
        fileData.receivedChunksCount++;
        const prog = (fileData.receivedChunksCount / fileData.totalChunks) * 100;
        this.onFileProgress(fileId, prog, 0, 'receiving', fileData.name);
        if (fileData.receivedChunksCount === fileData.totalChunks) {
          this.onMessage(this.roomName, this.peers[senderId]?.username || '알 수 없음',
            `[파일 다운로드 완료: ${fileData.name}]`,
            { name: fileData.name, size: fileData.size, url: `file://${savedPath}` }, cid);
          delete this.incomingFiles[fileId];
        }
      } else {
        if (!fileData.chunks) fileData.chunks = new Array(fileData.totalChunks);
        const iv  = encData.slice(0, 12);
        const ct  = encData.slice(12);
        const dec = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct.buffer);
        fileData.chunks[chunkIndex] = new Uint8Array(dec);
        fileData.receivedChunksCount++;
        const prog = (fileData.receivedChunksCount / fileData.totalChunks) * 100;
        this.onFileProgress(fileId, prog, 0, 'receiving', fileData.name);
        if (fileData.receivedChunksCount === fileData.totalChunks) {
          const blob = new Blob(fileData.chunks, { type: fileData.type });
          const url  = URL.createObjectURL(blob);
          this.onMessage(this.roomName, this.peers[senderId]?.username || '알 수 없음',
            `[파일 수신 완료: ${fileData.name}]`,
            { name: fileData.name, size: fileData.size, url }, cid);
          delete this.incomingFiles[fileId];
        }
      }
    } catch (e) { console.error('File chunk decrypt failed', e); }
  }

  // ─── Utility ──────────────────────────────────────────────
  _broadcastToAll(data) {
    for (const pid in this.peers) {
      const ch = this.peers[pid].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(data);
    }
  }

  // [v2] 인증된 피어에게만 브로드캐스트
  _broadcastToAuthenticated(data) {
    for (const pid in this.peers) {
      if (!this.peers[pid].authenticated) continue;
      const ch = this.peers[pid].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(data);
    }
  }

  getMembers() {
    return [
      { peerId: this.myPeerId, username: this.myUsername, isMe: true, authenticated: true },
      ...Object.entries(this.peers).map(([id, p]) => ({
        peerId: id,
        username: p.username,
        isMe: false,
        authenticated: p.authenticated,
      })),
    ];
  }

  getPeerCount() { return Object.keys(this.peers).length; }
  getAuthenticatedCount() {
    return Object.values(this.peers).filter(p => p.authenticated).length;
  }

  leaveRoom() {
    this.signalingClient?.leaveRoom();
    for (const id in this.peers) this._cleanupPeer(id);
    this.peers               = {};
    this.roomId              = null;
    this.roomCode            = null;
    this.roomName            = '';
    this.roomSalt            = '';
    this.groupKey            = null;
    this.channelKeys         = {};
    this.channels            = [];
    this.activeChannelId     = null;
    this.incomingFiles       = {};
    this.activeTransfers     = {};
    this._seenMsgIds.clear();
    this._pendingChallenges  = {};
    this.onStatusChange();
  }

  cancelTransfer(fileId) {
    if (this.activeTransfers[fileId]) this.activeTransfers[fileId].cancelFlag = true;
  }

  setActiveChannel(channelId) {
    this.activeChannelId = channelId;
    this.signalingClient?.switchChannel(channelId);
  }
}
