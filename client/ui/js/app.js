/**
 * TicMsg 메인 앱 로직
 * - 활성화 흐름 관리
 * - 3컬럼 UI (방 목록 | 채널 목록 | 채팅)
 * - 서버 시그널링 기반 방 참가
 * - 채널별 독립 암호화
 * - 영구 저장 메시지 복구
 */
document.addEventListener('DOMContentLoaded', async () => {
  // ─── State ─────────────────────────────────────────────
  let myUsername = '사용자_' + Math.floor(1000 + Math.random() * 9000);
  let activeRoomId = null;
  let activeChannelId = null;
  let chatRooms = {};      // roomId -> { name, channels, messages: {channelId: []}, persistent }
  let p2p = null;
  let sigClient = null;

  // ─── Tauri Invoke Wrapper ───────────────────────────────
  const tauriInvoke = async (cmd, args = {}) => {
    if (window.__TAURI__?.core) {
      try { return await window.__TAURI__.core.invoke(cmd, args); } catch (e) {
        console.error(`Tauri(${cmd}):`, e); return null;
      }
    }
    if (cmd === 'save_secure_data') { localStorage.setItem(args.filename, args.data); return true; }
    if (cmd === 'load_secure_data') { return localStorage.getItem(args.filename); }
    return null;
  };

  // ─── DOM Refs ───────────────────────────────────────────
  const screens = {
    activation: document.getElementById('screen-activation'),
    main: document.getElementById('screen-main'),
  };
  const myUsernameDisplay = document.getElementById('my-username-display');
  const myFriendCodeEl = document.getElementById('my-friend-code');
  const btnCopyMyCode = document.getElementById('btn-copy-my-code');
  const roomList = document.getElementById('room-list');
  const channelList = document.getElementById('channel-list');
  const createRoomKeyInput = document.getElementById('create-room-key');
  const btnCopyRoomKey = document.getElementById('btn-copy-room-key');
  const joinRoomKeyInput = document.getElementById('join-room-key');
  const createRoomPasswordInput = document.getElementById('create-room-password');
  const joinRoomPasswordInput = document.getElementById('join-room-password');
  const channelRoomTitle = document.getElementById('channel-room-title');
  const screenMain = document.getElementById('screen-main');
  const messageFeed = document.getElementById('message-feed');
  const messageInput = document.getElementById('message-input');
  const btnSend = document.getElementById('btn-send');
  const chatTitle = document.getElementById('chat-title');
  const chatMembersCount = document.getElementById('chat-members-count');
  const welcomeScreen = document.getElementById('welcome-screen');
  const chatScreen = document.getElementById('chat-screen');
  const fileInput = document.getElementById('file-input');
  const btnAttach = document.getElementById('btn-attach');
  const onlineIndicator = document.getElementById('online-indicator');
  const railBrand = document.querySelector('.rail-brand');

  const modals = {
    createRoom: document.getElementById('modal-create-room'),
    joinRoom: document.getElementById('modal-join-room'),
    joinByKey: document.getElementById('modal-join-by-key'),
    addChannel: document.getElementById('modal-add-channel'),
    roomSettings: document.getElementById('modal-room-settings'),
    security: document.getElementById('modal-security'),
    members: document.getElementById('modal-members'),
    settings: document.getElementById('modal-settings'),
    addFriend: document.getElementById('modal-add-friend'),
  };
  const showModal = (m) => { if(m) m.classList.remove('hidden'); };
  const hideModal = (m) => { if(m) m.classList.add('hidden'); };

  const generateRoomKey = () => crypto.randomUUID();
  const prepareCreateRoomModal = () => {
    if (createRoomKeyInput) createRoomKeyInput.value = generateRoomKey();
    if (createRoomPasswordInput) createRoomPasswordInput.value = '';
  };
  const prepareJoinRoomModal = () => {
    if (joinRoomKeyInput) joinRoomKeyInput.value = '';
    if (joinRoomPasswordInput) joinRoomPasswordInput.value = '';
  };

  document.querySelectorAll('.modal-close').forEach(btn => {
    btn.addEventListener('click', (e) => hideModal(e.target.closest('.modal')));
  });
  document.querySelectorAll('.modal').forEach(m => {
    m.addEventListener('click', (e) => { if (e.target === m) hideModal(m); });
  });

  // ─── Config ────────────────────────────────────────────
  const loadConfig = async () => {
    const s = await tauriInvoke('load_secure_data', { filename: 'config.json' });
    if (s) {
      try {
        const c = JSON.parse(s);
        if (c.username) myUsername = c.username;
      } catch (_) {}
    }
    myUsernameDisplay.textContent = myUsername;
    const settingsInput = document.getElementById('settings-username');
    if (settingsInput) settingsInput.value = myUsername;
  };

  const saveConfig = () =>
    tauriInvoke('save_secure_data', { filename: 'config.json', data: JSON.stringify({ username: myUsername }) });

  const loadHistory = async () => {
    const s = await tauriInvoke('load_secure_data', { filename: 'history.json' });
    if (s) { try { chatRooms = JSON.parse(s); } catch (_) {} }
    renderRoomList();
  };

  const saveHistory = () =>
    tauriInvoke('save_secure_data', { filename: 'history.json', data: JSON.stringify(chatRooms) });

  // ─── Activation Check ───────────────────────────────────
  const checkActivation = async () => {
    await AuthManager.init();
    if (!AuthManager.isActivated()) {
      screens.activation.classList.remove('hidden');
      screens.main.classList.add('hidden');
      return false;
    }
    screens.activation.classList.add('hidden');
    screens.main.classList.remove('hidden');
    return true;
  };

  // ─── Activation Form ────────────────────────────────────
  document.getElementById('btn-do-activate').addEventListener('click', async () => {
    const serverUrl = document.getElementById('activation-server-url').value.trim();
    const key = document.getElementById('activation-key-input').value.trim();
    if (!serverUrl) return showActivationError('서버 URL을 입력하세요.');
    if (!key) return showActivationError('활성화 키를 입력하세요.');

    await AuthManager.setServerUrl(serverUrl);

    // Ensure p2p is initialized to have a public key
    if (!p2p.localPublicKeyBase64) await p2p.initialize();

    const btn = document.getElementById('btn-do-activate');
    btn.disabled = true;
    btn.textContent = '활성화 중...';

    try {
      const result = await AuthManager.activate(key, p2p.localPublicKeyBase64);
      myUsername = result.username;
      myUsernameDisplay.textContent = myUsername;
      await saveConfig();

      // Initialize signaling
      initSignaling();

      screens.activation.classList.add('hidden');
      screens.main.classList.remove('hidden');
    } catch (e) {
      showActivationError(e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = '활성화';
    }
  });

  function showActivationError(msg) {
    const el = document.getElementById('activation-error');
    el.textContent = msg;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
  }

  // ─── Init P2P ───────────────────────────────────────────
  const initP2P = async () => {
    p2p = new P2PMeshManager({
      username: myUsername,
      onMessage: handleIncomingMessage,
      onStatusChange: handleStatusChange,
      onFileProgress: handleFileProgress,
      onChannelUpdate: handleChannelUpdate,
      onPeerUpdate: handlePeerUpdate,
    });
    await p2p.initialize();

    // Show public key (identity code)
    const myCode = await FriendCode.generateMyFriendCode(p2p.localKeyPair.publicKey);
    if (myFriendCodeEl) myFriendCodeEl.textContent = myCode;
  };

  // ─── Init Signaling ─────────────────────────────────────
  const initSignaling = () => {
    if (sigClient) sigClient.destroy();
    sigClient = new SignalingClient(AuthManager.getServerUrl(), {
      onConnected: (peerId) => {
        p2p.myPeerId = peerId;
        onlineIndicator.classList.add('online');
        onlineIndicator.title = '서버 연결됨';
      },
      onDisconnected: () => {
        onlineIndicator.classList.remove('online');
        onlineIndicator.title = '서버 연결 끊김 (재연결 중...)';
      },
      onError: (err) => console.error('[Signal Error]', err),
      onFriendRequest: handleFriendRequest,
    });
    p2p.attachSignaling(sigClient);
    sigClient.connect(
      AuthManager.getToken(),
      p2p.localPublicKeyBase64,
      p2p.myPeerId || crypto.randomUUID()
    );
  };

  // ─── P2P Callbacks ──────────────────────────────────────
  function handleIncomingMessage(roomName, sender, text, fileObj, channelId) {
    const rid = activeRoomId || roomName;
    if (!chatRooms[rid]) chatRooms[rid] = { name: roomName, channels: [], messages: {}, persistent: false };
    const cid = channelId || activeChannelId || 'default';
    if (!chatRooms[rid].messages[cid]) chatRooms[rid].messages[cid] = [];
    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const msg = { sender, text, timestamp, file: fileObj };
    chatRooms[rid].messages[cid].push(msg);
    saveHistory();
    if (rid === activeRoomId && cid === activeChannelId) appendMessageToFeed(msg);
    renderRoomList();
  }

  function handleStatusChange() {
    if (p2p?.roomId) {
      const rid = p2p.roomId;
      if (!chatRooms[rid]) chatRooms[rid] = { name: p2p.roomName, channels: p2p.channels, messages: {}, persistent: p2p.isPersistent };
      activeRoomId = rid;
      chatTitle.textContent = (p2p.channels.find(c => c.id === activeChannelId)?.name || p2p.roomName);
      chatMembersCount.textContent = `${p2p.getPeerCount() + 1}명 온라인`;
      welcomeScreen.classList.add('hidden');
      chatScreen.classList.remove('hidden');
      renderRoomList();
      renderChannelList();
    } else {
      goHome();
    }
  }

  function handleChannelUpdate(channels) {
    if (activeRoomId && chatRooms[activeRoomId]) {
      chatRooms[activeRoomId].channels = channels;
    }
    if (channels.length > 0 && !activeChannelId) {
      activeChannelId = channels[0].id;
      p2p.setActiveChannel(activeChannelId);
    }
    renderChannelList();
  }

  function handlePeerUpdate(event, peerId, username) {
    chatMembersCount.textContent = `${p2p.getPeerCount() + 1}명 온라인`;
  }

  async function handleFriendRequest(msg) {
    if (!msg || !msg.fromUsername || !msg.fromPublicKey) return;
    const accept = confirm(`${msg.fromUsername}님이 친구 요청을 보냈습니다. 친구로 추가하시겠습니까?`);
    if (!accept) return;

    let fingerprint = '';
    try {
      const remotePub = await CryptoHelper.importPublicKey(msg.fromPublicKey);
      fingerprint = await CryptoHelper.getFingerprint(remotePub);
    } catch (_) {}

    try {
      await FriendCode.addFriend(msg.fromPeerId, msg.fromUsername, msg.fromPublicKey, fingerprint);
      alert(`${msg.fromUsername}님이 친구로 추가되었습니다.`);
    } catch (e) {
      console.error('[Friend Request] add failed', e);
      alert('친구 추가 중 오류가 발생했습니다.');
    }
  }

  function updateRoomSelectionState() {
    if (!screenMain) return;
    screenMain.classList.toggle('room-selected', !!activeRoomId);
  }

  function goHome() {
    activeRoomId = null;
    activeChannelId = null;
    if (p2p?.roomId) {
      p2p.leaveRoom();
    }
    updateRoomSelectionState();
    chatTitle.textContent = '채팅을 선택하세요';
    channelRoomTitle.textContent = '';
    chatMembersCount.textContent = '';
    messageFeed.innerHTML = '';
    welcomeScreen.classList.remove('hidden');
    chatScreen.classList.add('hidden');
    renderRoomList();
    renderChannelList();
  }

  function handleFileProgress(fileId, progress, speed, status, filename) {
    const overlay = document.getElementById('file-transfer-overlay');
    if (!overlay) return;
    if (status === 'completed') { overlay.classList.add('hidden'); return; }
    overlay.classList.remove('hidden');
    document.getElementById('transfer-direction').textContent = status === 'sending' ? '전송 중...' : '수신 중...';
    document.getElementById('transfer-filename').textContent = filename || '파일';
    document.getElementById('transfer-speed').textContent = speed > 0 ? `${(speed / 1024).toFixed(1)} KB/s` : '';
    document.getElementById('transfer-progress-bar').style.width = `${progress}%`;
    document.getElementById('transfer-percentage').textContent = `${Math.round(progress)}%`;
  }

  // ─── Boot ───────────────────────────────────────────────
  await loadConfig();
  await FriendCode.loadFriends();
  await initP2P();
  await loadHistory();

  const isActivated = await checkActivation();
  if (isActivated) initSignaling();

  // ─── Settings Modal ─────────────────────────────────────
  document.getElementById('btn-settings').addEventListener('click', () => {
    document.getElementById('settings-username').value = myUsername;
    document.getElementById('settings-server-url').value = AuthManager.getServerUrl();
    showModal(modals.settings);
  });
  document.getElementById('btn-save-settings').addEventListener('click', async () => {
    const val = document.getElementById('settings-username').value.trim();
    const url = document.getElementById('settings-server-url').value.trim();
    if (val) {
      myUsername = val;
      myUsernameDisplay.textContent = val;
      if (p2p) p2p.setUsername(val);
      await saveConfig();
    }
    if (url) await AuthManager.setServerUrl(url);
    hideModal(modals.settings);
  });

  if (btnCopyMyCode) {
    btnCopyMyCode.addEventListener('click', () => {
      navigator.clipboard.writeText(myFriendCodeEl.textContent).then(() => {
        btnCopyMyCode.textContent = '복사됨!';
        setTimeout(() => { btnCopyMyCode.innerHTML = `<svg><use href="#icon-copy"/></svg> 복사`; }, 1500);
      });
    });
  }

  if (btnCopyRoomKey) {
    btnCopyRoomKey.addEventListener('click', () => {
      if (!createRoomKeyInput) return;
      navigator.clipboard.writeText(createRoomKeyInput.value).then(() => {
        btnCopyRoomKey.textContent = '복사됨!';
        setTimeout(() => { btnCopyRoomKey.textContent = '복사'; }, 1500);
      });
    });
  }

  if (railBrand) {
    railBrand.addEventListener('click', goHome);
    railBrand.style.cursor = 'pointer';
  }

  // ─── Create Room ────────────────────────────────────────
  document.getElementById('btn-create-room').addEventListener('click', () => {
    prepareCreateRoomModal();
    showModal(modals.createRoom);
  });
  document.getElementById('btn-do-create-room').addEventListener('click', async () => {
    const name = document.getElementById('create-room-name').value.trim();
    const roomKey = createRoomKeyInput?.value.trim();
    const password = createRoomPasswordInput?.value.trim();
    const persistent = document.getElementById('create-room-persistent').checked;
    if (!name) return alert('방 이름을 입력하세요.');
    if (!roomKey) return alert('생성된 방 비밀키가 없습니다. 새로고침 후 다시 시도하세요.');
    if (password && password.length < 6) return alert('방 비번은 6자 이상이어야 합니다.');

    try {
      const roomKeyHash = await CryptoHelper.sha256(roomKey);
      const roomPassword = password ? `${roomKey}:${password}` : roomKey;

      let roomData = null;
      if (AuthManager.isActivated()) {
        try {
          roomData = await AuthManager.getRoom(roomKeyHash);
        } catch (_) {}

        if (!roomData) {
          roomData = await AuthManager.createRoom(name, roomKeyHash, persistent);
        }
      }

      const roomSalt = roomData?.roomSalt || Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2,'0')).join('');
      const roomId = roomData?.roomId || roomKeyHash;

      chatRooms[roomId] = {
        name,
        channels: roomData?.channels || [{ id: 'default', name: '일반', position: 0 }],
        messages: {},
        persistent: !!persistent,
        roomKeyHash,
        roomSalt,
        roomSecretKey: roomKey,
        roomPassword: password || '',
      };
      activeRoomId = roomId;
      activeChannelId = (roomData?.channels || [{ id: 'default' }])[0]?.id;
      saveHistory();

      if (sigClient) {
        p2p.channels = chatRooms[roomId].channels;
        p2p.activeChannelId = activeChannelId;
        await p2p.joinRoomWithPassword(roomKeyHash, roomPassword, roomSalt);
        sigClient.joinRoom(roomKeyHash, activeChannelId);
      }

      hideModal(modals.createRoom);
      renderRoomList();
      renderChannelList();
      chatTitle.textContent = name;
      welcomeScreen.classList.add('hidden');
      chatScreen.classList.remove('hidden');
    } catch (e) {
      alert('방 생성 오류: ' + e.message);
    }
  });

  // ─── Join Room by Key ────────────────────────────────────
  document.getElementById('btn-join-room').addEventListener('click', () => {
    prepareJoinRoomModal();
    showModal(modals.joinByKey);
  });
  document.getElementById('btn-do-join-by-key').addEventListener('click', async () => {
    const roomKey = joinRoomKeyInput?.value.trim();
    const password = joinRoomPasswordInput?.value.trim();
    if (!roomKey) return alert('방 비밀키를 입력하세요.');

    try {
      const roomKeyHash = await CryptoHelper.sha256(roomKey);
      const roomPassword = password ? `${roomKey}:${password}` : roomKey;
      let roomData = null;

      if (AuthManager.isActivated()) {
        try { roomData = await AuthManager.getRoom(roomKeyHash); } catch (_) {}
      }

      if (!roomData) {
        alert('해당 방을 찾을 수 없습니다. 방 비밀번호를 확인하세요.');
        return;
      }

      const roomId = roomData.roomId;
      if (!chatRooms[roomId]) {
        chatRooms[roomId] = {
          name: roomData.name,
          channels: roomData.channels || [],
          messages: {},
          persistent: roomData.persistent,
          roomKeyHash,
          roomSalt: roomData.roomSalt,
          password,
        };
      }

      activeRoomId = roomId;
      activeChannelId = (roomData.channels || [{ id: 'default' }])[0]?.id;
      saveHistory();

      p2p.channels = chatRooms[roomId].channels;
      p2p.activeChannelId = activeChannelId;
      await p2p.joinRoomWithPassword(roomKeyHash, password, roomData.roomSalt);

      if (sigClient) sigClient.joinRoom(roomKeyHash, activeChannelId);

      // Fetch persistent messages if enabled
      if (roomData.persistent && activeChannelId && AuthManager.isActivated()) {
        fetchPersistentMessages(activeChannelId);
      }

      hideModal(modals.joinByKey);
      renderRoomList();
      renderChannelList();
      chatTitle.textContent = roomData.name;
      welcomeScreen.classList.add('hidden');
      chatScreen.classList.remove('hidden');
    } catch (e) {
      alert('방 참가 오류: ' + e.message);
    }
  });

  // ─── Fetch persistent messages ──────────────────────────
  async function fetchPersistentMessages(channelId) {
    if (!activeRoomId || !chatRooms[activeRoomId]?.persistent) return;
    try {
      const stored = await AuthManager.fetchMessages(channelId, 0);
      for (const msg of stored) {
        const key = await p2p._ensureChannelKey(channelId);
        if (!key) continue;
        try {
          const plaintext = await CryptoHelper.decrypt(key, msg.ciphertext);
          const obj = { sender: '[오프라인 메시지]', text: plaintext, timestamp: new Date(msg.sent_at).toLocaleTimeString(), file: null };
          if (!chatRooms[activeRoomId].messages[channelId]) chatRooms[activeRoomId].messages[channelId] = [];
          chatRooms[activeRoomId].messages[channelId].unshift(obj);
        } catch (_) {}
      }
      if (activeChannelId === channelId) renderMessages(activeRoomId, activeChannelId);
    } catch (e) { console.error('Failed to fetch persistent messages', e); }
  }

  // ─── Channel Switching ──────────────────────────────────
  function switchChannel(channelId) {
    activeChannelId = channelId;
    p2p.setActiveChannel(channelId);
    const ch = (chatRooms[activeRoomId]?.channels || p2p.channels).find(c => c.id === channelId);
    chatTitle.textContent = ch ? `# ${ch.name}` : '채널';
    renderMessages(activeRoomId, channelId);
    renderChannelList();
    // Fetch persistent messages
    if (chatRooms[activeRoomId]?.persistent) fetchPersistentMessages(channelId);
  }

  // ─── Add Channel ────────────────────────────────────────
  document.getElementById('btn-add-channel').addEventListener('click', () => showModal(modals.addChannel));
  document.getElementById('btn-do-add-channel').addEventListener('click', async () => {
    const name = document.getElementById('new-channel-name').value.trim();
    if (!name) return;
    if (!activeRoomId) return;

    try {
      const room = chatRooms[activeRoomId];
      let channelId = crypto.randomUUID();

      if (AuthManager.isActivated() && room?.roomKeyHash) {
        const roomData = await AuthManager.getRoom(room.roomKeyHash);
        if (roomData) {
          const newCh = await AuthManager.createChannel(roomData.roomId, name);
          channelId = newCh.channelId;
        }
      }

      const ch = { id: channelId, name, position: (chatRooms[activeRoomId].channels?.length || 0) };
      if (!chatRooms[activeRoomId].channels) chatRooms[activeRoomId].channels = [];
      chatRooms[activeRoomId].channels.push(ch);
      if (p2p) p2p.channels = chatRooms[activeRoomId].channels;
      saveHistory();
      renderChannelList();
      hideModal(modals.addChannel);
    } catch (e) { alert('채널 추가 오류: ' + e.message); }
  });

  // ─── Leave Room ─────────────────────────────────────────
  document.getElementById('btn-leave-room').addEventListener('click', () => {
    if (confirm('방을 나가시겠습니까?')) {
      const roomIdToRemove = activeRoomId;
      p2p?.leaveRoom();
      if (roomIdToRemove && chatRooms[roomIdToRemove]) {
        delete chatRooms[roomIdToRemove];
        saveHistory();
      }
      goHome();
      renderRoomList();
      renderChannelList();
    }
  });

  // ─── Security / Members ─────────────────────────────────
  document.getElementById('btn-show-security').addEventListener('click', async () => {
    if (p2p?.groupKey) {
      const fp = await CryptoHelper.getFingerprint(p2p.groupKey);
      document.getElementById('security-fingerprint').textContent = fp;
    }
    showModal(modals.security);
  });

  document.getElementById('btn-show-members').addEventListener('click', () => {
    const ul = document.getElementById('members-list-ul');
    ul.innerHTML = '';
    p2p?.getMembers().forEach(m => {
      const li = document.createElement('li');
      li.className = 'member-item';
      li.innerHTML = `<span>${m.username}${m.isMe ? ' (나)' : ''}</span><span class="member-role ${m.isMe ? '' : 'peer'}">${m.isMe ? '나' : '피어'}</span>`;
      ul.appendChild(li);
    });
    showModal(modals.members);
  });

  // ─── Rendering ───────────────────────────────────────────
  function renderRoomList() {
    if (!roomList) return;
    roomList.innerHTML = '';
    for (const rid in chatRooms) {
      const room = chatRooms[rid];
      const li = document.createElement('li');
      li.className = `room-item ${activeRoomId === rid ? 'active' : ''}`;
      const msgCount = Object.values(room.messages || {}).reduce((s, msgs) => s + msgs.length, 0);
      li.innerHTML = `
        <div class="room-icon">🏠</div>
        <div class="room-info">
          <div class="room-name">${room.name}</div>
          <div class="room-meta">${msgCount}개 메시지${room.persistent ? ' · 영구 저장' : ''}</div>
        </div>`;
      li.addEventListener('click', () => {
        activeRoomId = rid;
        const chs = room.channels || [];
        if (chs.length > 0) {
          activeChannelId = chs[0].id;
          if (p2p) p2p.activeChannelId = activeChannelId;
        }
        updateRoomSelectionState();
        channelRoomTitle.textContent = room.name;
        chatTitle.textContent = chs[0] ? `# ${chs[0].name}` : room.name;
        chatMembersCount.textContent = p2p?.roomId === rid ? `${p2p.getPeerCount() + 1}명 온라인` : '오프라인 (기록)';
        welcomeScreen.classList.add('hidden');
        chatScreen.classList.remove('hidden');
        renderRoomList();
        renderChannelList();
        renderMessages(rid, activeChannelId);
      });
      roomList.appendChild(li);
    }
  }

  function renderChannelList() {
    if (!channelList) return;
    channelList.innerHTML = '';
    const channels = (activeRoomId && chatRooms[activeRoomId]?.channels) || (p2p?.channels) || [];
    if (activeRoomId && chatRooms[activeRoomId]) {
      channelRoomTitle.textContent = chatRooms[activeRoomId].name;
    }
    channels.forEach(ch => {
      const li = document.createElement('li');
      li.className = `channel-item ${activeChannelId === ch.id ? 'active' : ''}`;
      li.innerHTML = `
        <svg class="channel-hash"><use href="#icon-hash"/></svg>
        <span class="channel-name">${ch.name}</span>`;
      li.addEventListener('click', () => switchChannel(ch.id));
      channelList.appendChild(li);
    });
  }

  function renderMessages(roomId, channelId) {
    if (!messageFeed) return;
    messageFeed.innerHTML = '';
    const msgs = chatRooms[roomId]?.messages?.[channelId] || [];
    msgs.forEach(m => appendMessageToFeed(m));
  }

  function appendMessageToFeed(msg) {
    const isOut = msg.sender === myUsername;
    const wrap = document.createElement('div');
    wrap.className = `message-wrapper ${isOut ? 'outgoing' : 'incoming'}`;

    if (!isOut) {
      const s = document.createElement('div');
      s.className = 'msg-sender';
      s.textContent = msg.sender;
      wrap.appendChild(s);
    }

    const box = document.createElement('div');
    box.className = 'message-box';

    if (msg.file) {
      box.innerHTML = `
        <div class="file-message">
          <div class="file-icon"><svg><use href="#icon-file"/></svg></div>
          <div class="file-details">
            <a href="${msg.file.url}" download="${msg.file.name}" class="file-name">${msg.file.name}</a>
            <span class="file-size">${(msg.file.size / (1024 * 1024)).toFixed(2)} MB</span>
          </div>
        </div>`;
    } else {
      box.textContent = msg.text;
    }

    const meta = document.createElement('div');
    meta.className = 'msg-meta';
    meta.innerHTML = `<span class="e2ee-lock"><svg><use href="#icon-lock"/></svg></span><span>${msg.timestamp}</span>`;
    box.appendChild(meta);
    wrap.appendChild(box);
    messageFeed.appendChild(wrap);
    messageFeed.scrollTop = messageFeed.scrollHeight;
  }

  // ─── Send Message ────────────────────────────────────────
  btnSend.addEventListener('click', sendMessage);
  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text) return;
    if (!activeRoomId || !activeChannelId || !p2p?.roomId) {
      alert('먼저 방에 참가해야 합니다.');
      return;
    }
    await p2p.sendMessage(text, activeChannelId);
    messageInput.value = '';
  }

  // ─── File Attach ─────────────────────────────────────────
  btnAttach.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file || !p2p?.roomId) return;
    if (file.size > 500 * 1024 * 1024) { alert('최대 500MB까지 전송 가능합니다.'); fileInput.value = ''; return; }
    try { await p2p.sendFile(file, activeChannelId); } catch (err) { alert('파일 전송 오류: ' + err.message); }
    fileInput.value = '';
  });

  // ─── Sidebar Room Panel Tabs ──────────────────────────────
  document.querySelectorAll('.sidebar-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.sidebar-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const panelId = tab.dataset.panel;
      document.getElementById('panel-' + panelId).classList.add('active');
    });
  });

  // ─── Add Friend (server relay) ───────────────────────────
  document.getElementById('btn-add-friend')?.addEventListener('click', () => showModal(modals.addFriend));
  document.getElementById('btn-generate-friend-req')?.addEventListener('click', async () => {
    const codeRaw = document.getElementById('friend-code-input').value.trim();
    if (!codeRaw) return alert('상대방 친구 코드를 입력하세요.');
    try {
      const remotePubKey = await FriendCode.parseFriendCode(codeRaw);
      const remotePubKeyStr = await CryptoHelper.exportPublicKey(remotePubKey);
      const targetKeyHash = await CryptoHelper.sha256(remotePubKeyStr);

      // Generate offer
      const offerPayload = { sdp: '서버 시그널링 사용', username: myUsername, publicKey: p2p.localPublicKeyBase64 };
      sigClient?.sendFriendRequest(targetKeyHash, offerPayload);

      alert('친구 요청을 전송했습니다. 상대방이 온라인이면 자동으로 연결됩니다.');
    } catch (e) { alert('오류: ' + e.message); }
  });

  // ─── Friend List & Load ──────────────────────────────────
  async function loadFriends() {
    const listEl = document.getElementById('friend-list');
    if (!listEl) return;
    try {
      const res = await fetch(`${AuthManager.getServerUrl()}/api/friends`, {
        headers: AuthManager.authHeaders()
      });
      if (!res.ok) return;
      const data = await res.json();
      listEl.innerHTML = data.friends.map(f => `
        <li class="friend-item">
          <div class="status-dot ${f.status === 1 ? 'status-online' : ''}"></div>
          ${f.username}
        </li>
      `).join('');
    } catch (e) { console.error('친구 목록 로딩 실패', e); }
  }

  // Bind Add Friend UI
  document.getElementById('btn-add-friend-ui')?.addEventListener('click', () => showModal(modals.addFriend));

  // Initial render
  renderRoomList();
  renderChannelList();
  loadFriends();
});
