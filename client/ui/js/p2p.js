/**
 * P2PMeshManager - 그리드넷 메시 P2P 매니저
 *
 * 서버는 WebRTC 시그널링(SDP/ICE 중계)만 담당.
 * 모든 채팅 데이터는 WebRTC DataChannel을 통해 직접 P2P 전송 (E2EE).
 *
 * 방 키(비밀번호)에서 PBKDF2로 그룹키 파생 → 서버에는 SHA-256 해시만.
 * 채널별 독립 키: HKDF(그룹키, channelId)
 *
 * 그리드넷 원리:
 *   - 새 피어가 방에 입장 → 서버가 기존 피어 목록 전달
 *   - 새 피어가 기존 피어 전원에게 WebRTC offer 발송 (서버 중계)
 *   - 풀 메시 형성 후 서버 없이 직접 통신
 *   - 메시지는 모든 연결된 피어에게 브로드캐스트 (gossip)
 */
class P2PMeshManager {
  constructor(options = {}) {
    this.myPeerId = null; // Set by signaling server after auth
    this.myUsername = options.username || '사용자';
    this.onMessage = options.onMessage || (() => {});
    this.onStatusChange = options.onStatusChange || (() => {});
    this.onFileProgress = options.onFileProgress || (() => {});
    this.onChannelUpdate = options.onChannelUpdate || (() => {});
    this.onPeerUpdate = options.onPeerUpdate || (() => {});

    // Local keypair (long-term identity)
    this.localKeyPair = null;
    this.localPublicKeyBase64 = null;

    // Peers: peerId -> { connection, dataChannel, username, publicKey, sharedKey }
    this.peers = {};

    // Room state
    this.roomId = null;
    this.roomName = '';
    this.roomSalt = '';
    this.isPersistent = false;
    this.groupKey = null;       // Derived from room password
    this.channelKeys = {};      // channelId -> CryptoKey
    this.channels = [];         // [{ id, name, position }]
    this.activeChannelId = null;

    // File transfer state
    this.incomingFiles = {};
    this.activeTransfers = {};

    // Signaling client (set externally)
    this.signalingClient = null;

    // WebRTC config with multiple STUN servers
    this.rtcConfig = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ]
    };

    // Pending connection (before remote description set)
    this._pendingConnections = {}; // peerId -> { pc, dc }
  }

  // ─── Initialize (load or generate long-term keypair) ────
  async initialize() {
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
      } catch (_) {
        // Corrupted - regenerate
      }
    }

    // Generate fresh keypair
    this.localKeyPair = await CryptoHelper.generateAndSaveIdentityKeyPair(saveKp);
    this.localPublicKeyBase64 = await CryptoHelper.exportPublicKey(this.localKeyPair.publicKey);
  }

  setUsername(username) { this.myUsername = username; }

  // ─── Attach Signaling Client ──────────────────────────
  attachSignaling(sigClient) {
    this.signalingClient = sigClient;

    sigClient.onRoomJoined = async (msg) => {
      this.roomId = msg.roomId;
      this.roomName = msg.roomName;
      this.roomSalt = msg.roomSalt;
      this.isPersistent = msg.persistent;
      this.channels = msg.channels || [];

      // Key derivation happens after password is provided externally
      // (see joinRoomWithPassword)

      this.onChannelUpdate(this.channels);
      this.onStatusChange();

      // Connect to all existing peers (full mesh)
      for (const peer of (msg.peers || [])) {
        await this._initiateConnection(peer.peerId, peer.username, peer.publicKey);
      }
    };

    sigClient.onPeerJoined = async (msg) => {
      this.onPeerUpdate('joined', msg.peerId, msg.username);
      // Existing peers don't initiate; new peer sends offers to them
      // (server notifies us, but the new peer initiates)
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

  // ─── Join Room with Password ──────────────────────────
  async joinRoomWithPassword(roomKeyHash, roomPassword, roomSalt) {
    this.groupKey = await CryptoHelper.deriveRoomGroupKey(roomPassword, roomSalt);
    this.channelKeys = {};
    // Pre-derive channel keys
    for (const ch of this.channels) {
      this.channelKeys[ch.id] = await CryptoHelper.deriveChannelKey(this.groupKey, ch.id);
    }
    this.signalingClient?.joinRoom(roomKeyHash, this.activeChannelId);
  }

  // Ensure channel key is derived
  async _ensureChannelKey(channelId) {
    if (!this.channelKeys[channelId] && this.groupKey) {
      this.channelKeys[channelId] = await CryptoHelper.deriveChannelKey(this.groupKey, channelId);
    }
    return this.channelKeys[channelId];
  }

  // ─── WebRTC Connection: Initiator side ───────────────
  async _initiateConnection(remotePeerId, remoteUsername, remotePubKeyStr) {
    if (this.peers[remotePeerId]) return; // Already connected

    const pc = new RTCPeerConnection(this.rtcConfig);
    const dc = pc.createDataChannel('chat', { ordered: true });

    this.peers[remotePeerId] = {
      connection: pc,
      dataChannel: dc,
      username: remoteUsername,
      publicKey: remotePubKeyStr ? await CryptoHelper.importPublicKey(remotePubKeyStr) : null,
      sharedKey: null,
    };

    this._setupDataChannel(remotePeerId, dc);

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.signalingClient?.sendSignal(remotePeerId, {
          type: 'ice',
          candidate: e.candidate,
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

  // ─── WebRTC Connection: Responder side ───────────────
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
      };

      pc.ondatachannel = (e) => {
        this.peers[fromPeerId].dataChannel = e.channel;
        this._setupDataChannel(fromPeerId, e.channel);
      };

      pc.onicecandidate = (e) => {
        if (e.candidate) {
          this.signalingClient?.sendSignal(fromPeerId, {
            type: 'ice',
            candidate: e.candidate,
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
      if (peer && peer.connection) {
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
      if (peer && peer.connection && payload.candidate) {
        try {
          await peer.connection.addIceCandidate(new RTCIceCandidate(payload.candidate));
        } catch (_) {}
      }
    }
  }

  // ─── DataChannel Setup ───────────────────────────────
  _setupDataChannel(peerId, channel) {
    channel.onopen = async () => {
      console.log(`[Mesh] Connected to ${this.peers[peerId]?.username}`);
      if (this.peers[peerId]?.publicKey && this.localKeyPair) {
        try {
          const sharedKey = await CryptoHelper.deriveSharedKey(
            this.localKeyPair.privateKey,
            this.peers[peerId].publicKey
          );
          this.peers[peerId].sharedKey = sharedKey;
        } catch (_) {}
      }
      this.onStatusChange();
    };

    channel.onclose = () => {
      this._cleanupPeer(peerId);
      this.onStatusChange();
    };

    channel.onerror = (err) => console.error('[DataChannel Error]', err);

    channel.onmessage = async (event) => {
      if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
        // Binary file chunk
        const buf = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
        this._handleFileChunk(buf, peerId);
        return;
      }

      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }

      switch (packet.type) {
        case 'CHAT_MSG':
          await this._handleChatMsg(packet, peerId);
          break;
        case 'FILE_META':
          await this._handleFileMeta(packet, peerId);
          break;
        case 'MESH_RELAY':
          // Grid-net relay: re-broadcast to other peers (gossip)
          this._relayToOthers(packet, peerId);
          await this._handleChatMsg(packet.inner, peerId);
          break;
      }
    };
  }

  _cleanupPeer(peerId) {
    const peer = this.peers[peerId];
    if (!peer) return;
    try { peer.dataChannel?.close(); } catch (_) {}
    try { peer.connection?.close(); } catch (_) {}
    delete this.peers[peerId];
  }

  // ─── Grid-Net Relay (gossip broadcast) ───────────────
  // Re-send messages to peers who aren't directly connected to the sender
  _relayToOthers(packet, fromPeerId) {
    if (!packet.ttl || packet.ttl <= 0) return; // Prevent infinite loops
    const relayPacket = { ...packet, ttl: packet.ttl - 1 };
    const data = JSON.stringify(relayPacket);
    for (const id in this.peers) {
      if (id === fromPeerId) continue;
      const ch = this.peers[id].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(data);
    }
  }

  // ─── Send Message ─────────────────────────────────────
  async sendMessage(text, channelId = null) {
    const cid = channelId || this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;

    const encrypted = await CryptoHelper.encrypt(key, text);
    const packet = JSON.stringify({
      type: 'CHAT_MSG',
      channelId: cid,
      ciphertext: encrypted,
      ttl: 3, // Grid-net relay TTL
    });

    let sent = false;
    for (const peerId in this.peers) {
      const ch = this.peers[peerId].dataChannel;
      if (ch && ch.readyState === 'open') {
        ch.send(packet);
        sent = true;
      }
    }

    // If persistent, push to server too
    if (this.isPersistent && cid && this.signalingClient) {
      this.signalingClient.storeMessage(cid, encrypted, Date.now());
    }

    this.onMessage(this.roomName, this.myUsername, text, null, cid);
  }

  async _handleChatMsg(packet, fromPeerId) {
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

  // ─── File Transfer ────────────────────────────────────
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

    this._broadcastToAll(metaPacket);
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
          const ch = Object.values(this.peers)[0]?.dataChannel;
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
      this.onMessage(this.roomName, this.peers[fromPeerId]?.username || '알 수 없음', `[파일 수신 대기: ${meta.name}]`, null, meta.channelId);
    } catch (e) { console.error('File meta decrypt failed', e); }
  }

  async _handleFileChunk(arrayBuffer, senderId) {
    const fileId = new TextDecoder().decode(new Uint8Array(arrayBuffer, 0, 36));
    const fileData = this.incomingFiles[fileId];
    if (!fileData) return;

    const chunkIndex = new DataView(arrayBuffer, 36, 4).getUint32(0);
    const encData = new Uint8Array(arrayBuffer, 40);
    const cid = fileData.channelId || this.activeChannelId;
    const key = await this._ensureChannelKey(cid);
    if (!key) return;

    const rawGroupKey = await CryptoHelper.exportSymmetricKey(key);
    const rawGroupKeyBytes = new Uint8Array(CryptoHelper.base64ToArrayBuffer(rawGroupKey));

    try {
      let decryptedBytes;
      if (window.__TAURI__?.core) {
        const res = await window.__TAURI__.core.invoke('decrypt_file_chunk', {
          key: Array.from(rawGroupKeyBytes),
          encryptedChunk: Array.from(encData),
        });
        decryptedBytes = new Uint8Array(res);
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
        const iv = encData.slice(0, 12);
        const ct = encData.slice(12);
        const dec = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct.buffer);
        fileData.chunks[chunkIndex] = new Uint8Array(dec);
        fileData.receivedChunksCount++;
        const prog = (fileData.receivedChunksCount / fileData.totalChunks) * 100;
        this.onFileProgress(fileId, prog, 0, 'receiving', fileData.name);
        if (fileData.receivedChunksCount === fileData.totalChunks) {
          const blob = new Blob(fileData.chunks, { type: fileData.type });
          const url = URL.createObjectURL(blob);
          this.onMessage(this.roomName, this.peers[senderId]?.username || '알 수 없음',
            `[파일 수신 완료: ${fileData.name}]`,
            { name: fileData.name, size: fileData.size, url }, cid);
          delete this.incomingFiles[fileId];
        }
      }
    } catch (e) { console.error('File chunk decrypt failed', e); }
  }

  // ─── Utility ──────────────────────────────────────────
  _broadcastToAll(data) {
    for (const pid in this.peers) {
      const ch = this.peers[pid].dataChannel;
      if (ch && ch.readyState === 'open') ch.send(data);
    }
  }

  getMembers() {
    return [
      { peerId: this.myPeerId, username: this.myUsername, isMe: true },
      ...Object.entries(this.peers).map(([id, p]) => ({ peerId: id, username: p.username, isMe: false })),
    ];
  }

  getPeerCount() { return Object.keys(this.peers).length; }

  leaveRoom() {
    this.signalingClient?.leaveRoom();
    for (const id in this.peers) this._cleanupPeer(id);
    this.peers = {};
    this.roomId = null;
    this.roomName = '';
    this.groupKey = null;
    this.channelKeys = {};
    this.channels = [];
    this.activeChannelId = null;
    this.incomingFiles = {};
    this.activeTransfers = {};
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
