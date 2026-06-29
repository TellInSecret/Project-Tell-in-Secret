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
    await LocalIdentity.init();
    if (!LocalIdentity.isSetup()) {
      screens.activation.classList.remove('hidden');
      screens.main.classList.add('hidden');
      return false;
    }
    screens.activation.classList.add('hidden');
    screens.main.classList.remove('hidden');
    return true;
  };

  // ─── Activation Form (v2: 서버리스, 사용자명만 설정) ────
  document.getElementById('btn-do-activate')?.addEventListener('click', async () => {
    const username = document.getElementById('activation-username-input')?.value.trim();
    if (!username) return showActivationError('사용자명을 입력하세요.');

    const btn = document.getElementById('btn-do-activate');
    if (btn) {
      btn.disabled = true;
      btn.textContent = '설정 중...';
    }

    try {
      await LocalIdentity.setUsername(username);
      myUsername = username;
      myUsernameDisplay.textContent = myUsername;
      await saveConfig();

      // Initialize signaling (serverless mode)
      initSignaling();

      screens.activation.classList.add('hidden');
      screens.main.classList.remove('hidden');
    } catch (e) {
      showActivationError(e.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = '시작하기';
      }
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

  // ─── Init Signaling (v2: 서버리스 PeerJS 브로커 시그널링) ─
  const initSignaling = () => {
    if (sigClient) { try { sigClient.destroy(); } catch (_) {} }

    // 피어 ID 보장 (initialize 이후 호출되므로 localPublicKeyBase64 사용 가능)
    if (!p2p.myPeerId) p2p.myPeerId = crypto.randomUUID();

    // 서버리스 시그널링 객체 생성.
    // onConnected/onDisconnected/onError만 여기서 지정하고,
    // onRoomJoined/onPeerJoined/onPeerLeft/onSignal은 attachSignaling이 덮어쓴다.
    sigClient = new ServerlessSignaling({
      username: myUsername,
      onConnected: (peerId) => {
        p2p.myPeerId = peerId;
        onlineIndicator.classList.add('online');
        onlineIndicator.title = '서버리스 P2P 연결됨';
      },
      onDisconnected: () => {
        onlineIndicator.classList.remove('online');
        onlineIndicator.title = '시그널링 연결 끊김 (재연결 중...)';
      },
      onError: (err) => console.error('[Signal Error]', err),
    });

    // p2p의 시그널링 콜백 연결 (onRoomJoined/onPeerJoined/onPeerLeft/onSignal 등록)
    p2p.attachSignaling(sigClient);

    // PeerJS 브로커 연결 시작 (라이브러리 없으면 내부에서 manual 폴백)
    sigClient.connect(p2p.myPeerId, p2p.localPublicKeyBase64);
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

  // ─── Settings Modal (v2: 서버 설정 제거) ───────────────
  document.getElementById('btn-settings')?.addEventListener('click', () => {
    document.getElementById('settings-username').value = myUsername;
    showModal(modals.settings);
  });
  document.getElementById('btn-save-settings')?.addEventListener('click', async () => {
    const val = document.getElementById('settings-username')?.value.trim();
    if (val) {
      myUsername = val;
      myUsernameDisplay.textContent = val;
      if (p2p) p2p.setUsername(val);
      await LocalIdentity.setUsername(val);
      await saveConfig();
    }
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

  // ─── Create Room (v2: 서버리스, 로컬 전용) ──────────────
  document.getElementById('btn-create-room')?.addEventListener('click', () => {
    prepareCreateRoomModal();
    showModal(modals.createRoom);
  });
  document.getElementById('btn-do-create-room')?.addEventListener('click', async () => {
    const name = document.getElementById('create-room-name')?.value.trim();
    const roomKey = createRoomKeyInput?.value.trim();
    const password = createRoomPasswordInput?.value.trim();
    const persistent = document.getElementById('create-room-persistent')?.checked;
    if (!name) return alert('방 이름을 입력하세요.');
    if (!roomKey) return alert('생성된 방 비밀키가 없습니다. 새로고침 후 다시 시도하세요.');
    if (password && password.length < 6) return alert('방 비번은 6자 이상이어야 합니다.');

    try {
      if (!sigClient) initSignaling();

      // [v2] 방 코드 하나로 salt/roomId/groupKey를 결정론적으로 파생.
      // password는 방 코드와 결합해 키 파생에 반영 → 같은 코드라도 비번이 다르면 다른 방.
      const joinCode = password ? `${roomKey}:${password}` : roomKey;
      await p2p.joinRoomWithCode(joinCode, name);

      // 파생된 공개 식별자(roomId)를 로컬 히스토리 키로 사용
      const roomId = p2p.roomId;
      // [채널 ID 통일] 모든 피어가 동일하게 쓰는 결정론적 기본 채널 ID.
      // onRoomJoined가 나중에 와도 같은 값이라 키 불일치가 없다.
      const channelId = CryptoHelper.defaultChannelId(roomId);
      const channels = [{ id: channelId, name: '일반', position: 0 }];
      chatRooms[roomId] = {
        name,
        channels,
        messages: {},
        persistent: !!persistent,
        roomSalt: p2p.roomSalt,
        roomSecretKey: roomKey,
        roomPassword: password || '',
      };
      activeRoomId = roomId;
      activeChannelId = channelId;
      p2p.channels = channels;
      p2p.setActiveChannel(activeChannelId);
      saveHistory();

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

  // ─── Join Room by Key (v2: 서버리스, 로컬 전용) ─────────
  document.getElementById('btn-join-room')?.addEventListener('click', () => {
    prepareJoinRoomModal();
    showModal(modals.joinByKey);
  });
  document.getElementById('btn-do-join-by-key')?.addEventListener('click', async () => {
    const roomKey = joinRoomKeyInput?.value.trim();
    const password = joinRoomPasswordInput?.value.trim();
    if (!roomKey) return alert('방 비밀키를 입력하세요.');

    try {
      if (!sigClient) initSignaling();

      // [v2] 생성 측과 동일하게 방 코드(+비번)로 키를 결정론적으로 파생.
      // 양쪽이 같은 코드를 쓰면 같은 roomId/salt/groupKey가 나와 연결·복호화가 일치.
      const joinCode = password ? `${roomKey}:${password}` : roomKey;
      await p2p.joinRoomWithCode(joinCode);

      const roomId = p2p.roomId;
      // [채널 ID 통일] 생성 측과 같은 결정론적 채널 ID 사용 → 키 일치 보장
      const channelId = CryptoHelper.defaultChannelId(roomId);
      if (!chatRooms[roomId]) {
        chatRooms[roomId] = {
          name: '방 ' + roomId.substring(0, 8),
          channels: [{ id: channelId, name: '일반', position: 0 }],
          messages: {},
          persistent: false,
          roomSalt: p2p.roomSalt,
          roomSecretKey: roomKey,
          roomPassword: password || '',
        };
      }

      activeRoomId = roomId;
      activeChannelId = channelId;
      p2p.channels = chatRooms[roomId].channels;
      p2p.setActiveChannel(activeChannelId);
      saveHistory();

      hideModal(modals.joinByKey);
      renderRoomList();
      renderChannelList();
      chatTitle.textContent = chatRooms[roomId].name;
      welcomeScreen.classList.add('hidden');
      chatScreen.classList.remove('hidden');
    } catch (e) {
      alert('방 참가 오류: ' + e.message);
    }
  });

  // ─── Fetch persistent messages (v2: 서버리스, 기능 제거) ──
  async function fetchPersistentMessages(channelId) {
    // v2는 서버리스이므로 서버에서 메시지를 가져올 수 없음
    // 로컬 저장소에서만 메시지 복구
    return;
  }

  // ─── Channel Switching (v2: persistent fetch 제거) ──────
  function switchChannel(channelId) {
    activeChannelId = channelId;
    p2p.setActiveChannel(channelId);
    const ch = (chatRooms[activeRoomId]?.channels || p2p.channels).find(c => c.id === channelId);
    chatTitle.textContent = ch ? `# ${ch.name}` : '채널';
    renderMessages(activeRoomId, channelId);
    renderChannelList();
    // v2: 서버에서 메시지 가져오기 제거
  }

  // ─── Add Channel (v2: 서버리스, 로컬 전용) ──────────────
  document.getElementById('btn-add-channel')?.addEventListener('click', () => showModal(modals.addChannel));
  document.getElementById('btn-do-add-channel')?.addEventListener('click', async () => {
    const name = document.getElementById('new-channel-name')?.value.trim();
    if (!name) return;
    if (!activeRoomId) return;

    try {
      const room = chatRooms[activeRoomId];
      // [v2] 채널 ID를 이름에서 결정론적으로 파생 → 같은 이름 채널을 만든
      // 다른 피어와 자동으로 같은 채널 ID/키를 공유 (서버리스 동기화 불필요).
      const channelId = await CryptoHelper.channelIdFromName(activeRoomId, name);

      if (!chatRooms[activeRoomId].channels) chatRooms[activeRoomId].channels = [];
      // 이미 같은 채널이 있으면 추가하지 않고 그 채널로 전환
      if (chatRooms[activeRoomId].channels.some(c => c.id === channelId)) {
        switchChannel(channelId);
        hideModal(modals.addChannel);
        return;
      }

      const ch = { id: channelId, name, position: chatRooms[activeRoomId].channels.length };
      chatRooms[activeRoomId].channels.push(ch);
      if (p2p) p2p.channels = chatRooms[activeRoomId].channels;
      saveHistory();
      renderChannelList();
      hideModal(modals.addChannel);
    } catch (e) { alert('채널 추가 오류: ' + e.message); }
  });

  // ─── Leave Room ─────────────────────────────────────────
  document.getElementById('btn-leave-room')?.addEventListener('click', () => {
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
  document.getElementById('btn-show-security')?.addEventListener('click', async () => {
    if (p2p?.groupKey) {
      const fp = await CryptoHelper.getFingerprint(p2p.groupKey);
      document.getElementById('security-fingerprint').textContent = fp;
    }
    showModal(modals.security);
  });

  document.getElementById('btn-show-members')?.addEventListener('click', () => {
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

  // ─── Add Friend (server relay) (v2: 서버리스, 기능 제거) ──
  document.getElementById('btn-add-friend')?.addEventListener('click', () => showModal(modals.addFriend));
  document.getElementById('btn-generate-friend-req')?.addEventListener('click', async () => {
    const codeRaw = document.getElementById('friend-code-input')?.value.trim();
    if (!codeRaw) return alert('상대방 친구 코드를 입력하세요.');
    try {
      const remotePubKey = await FriendCode.parseFriendCode(codeRaw);
      const remotePubKeyStr = await CryptoHelper.exportPublicKey(remotePubKey);
      const targetKeyHash = await CryptoHelper.sha256(remotePubKeyStr);

      // v2: 서버리스이므로 시그널링 서버를 통한 친구 요청 불가
      // 대신 친구 코드를 로컬에 저장하고 수동으로 방 코드 공유
      alert('v2 서버리스 버전에서는 방 코드를 직접 공유하여 연결하세요.');
    } catch (e) { alert('오류: ' + e.message); }
  });

  // Initial render
  renderRoomList();
  renderChannelList();
});
