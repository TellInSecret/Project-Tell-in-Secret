/**
 * TicMsg Server - Main Entry Point
 * Express REST API + WebSocket Signaling Server (sqlite/sqlite3 Async version)
 *
 * Security:
 *  - Passwords: bcrypt (cost 12)
 *  - Activation keys: SHA-256 hash only
 *  - Room keys: SHA-256 hash only (original never reaches server)
 *  - JWT: HS256, 7-day expiry
 *  - Messages (persistent): ciphertext only, server cannot decrypt
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ─────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const BCRYPT_ROUNDS = 12;
const MAX_DEVICES = 5;
const ACTIVATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MSG_PURGE_INTERVAL_MS = 60 * 60 * 1000;   // 1 hour
const MSG_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

console.log(`[TicMsg] JWT secret initialized (${JWT_SECRET.length} chars)`);

// ─────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// JWT Helpers
// ─────────────────────────────────────────────
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: '인증이 필요합니다.' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: '토큰이 만료되었거나 유효하지 않습니다.' });
  req.user = payload;
  next();
}

// ─────────────────────────────────────────────
// REST API - Auth
// ─────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, publicKey, deviceName } = req.body;
    if (!username || !password || !publicKey)
      return res.status(400).json({ error: '아이디, 비밀번호, 공개키는 필수입니다.' });

    if (username.length < 3 || username.length > 32)
      return res.status(400).json({ error: '아이디는 3~32자여야 합니다.' });

    if (password.length < 8)
      return res.status(400).json({ error: '비밀번호는 8자 이상이어야 합니다.' });

    const existing = await db.users.findByUsername(username);
    if (existing) return res.status(409).json({ error: '이미 사용 중인 아이디입니다.' });

    const publicKeyHash = db.sha256(publicKey);
    const keyExists = await db.devices.findByKeyHash(publicKeyHash);
    if (keyExists) return res.status(409).json({ error: '이미 등록된 공개키입니다.' });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userId = db.newId();
    const deviceId = db.newId();
    const t = db.now();

    await db.users.create({
      id: userId,
      username,
      password_hash: passwordHash,
      created_at: t,
    });

    await db.devices.create({
      id: deviceId,
      user_id: userId,
      public_key: publicKey,
      public_key_hash: publicKeyHash,
      device_name: deviceName || '기기 1',
      registered_at: t,
    });

    const token = signToken({ userId, username, deviceId });
    res.status(201).json({
      message: '가입 완료! 활성화 키를 발급받으세요.',
      token,
      userId,
      deviceId,
    });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });

    const user = await db.users.findByUsername(username);
    if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

    const devices = await db.devices.listByUser(user.id);
    const token = signToken({ userId: user.id, username: user.username });
    res.json({ token, userId: user.id, devices });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ─────────────────────────────────────────────
// REST API - Devices
// ─────────────────────────────────────────────

// GET /api/devices
app.get('/api/devices', authMiddleware, async (req, res) => {
  const devices = await db.devices.listByUser(req.user.userId);
  res.json({ devices });
});

// POST /api/devices (add a new device, max 5)
app.post('/api/devices', authMiddleware, async (req, res) => {
  try {
    const { publicKey, deviceName } = req.body;
    if (!publicKey) return res.status(400).json({ error: '공개키가 필요합니다.' });

    const deviceCountResult = await db.devices.countByUser(req.user.userId);
    const cnt = deviceCountResult ? deviceCountResult.cnt : 0;
    if (cnt >= MAX_DEVICES) {
      return res.status(403).json({
        error: `최대 ${MAX_DEVICES}대까지 등록 가능합니다. 기존 기기를 삭제한 후 다시 시도하세요.`,
        code: 'DEVICE_LIMIT_REACHED',
        currentCount: cnt,
        maxDevices: MAX_DEVICES,
      });
    }

    const publicKeyHash = db.sha256(publicKey);
    const keyExists = await db.devices.findByKeyHash(publicKeyHash);
    if (keyExists) return res.status(409).json({ error: '이미 등록된 공개키입니다.' });

    const deviceId = db.newId();
    await db.devices.create({
      id: deviceId,
      user_id: req.user.userId,
      public_key: publicKey,
      public_key_hash: publicKeyHash,
      device_name: deviceName || `기기 ${cnt + 1}`,
      registered_at: db.now(),
    });

    res.status(201).json({ deviceId, message: '기기가 등록되었습니다.' });
  } catch (e) {
    console.error('[add-device]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// DELETE /api/devices/:id
app.delete('/api/devices/:id', authMiddleware, async (req, res) => {
  const result = await db.devices.delete(req.params.id, req.user.userId);
  if (result.changes === 0)
    return res.status(404).json({ error: '기기를 찾을 수 없습니다.' });
  res.json({ message: '기기가 삭제되었습니다.' });
});

// ─────────────────────────────────────────────
// REST API - Activation
// ─────────────────────────────────────────────

// POST /api/activate/issue  (server issues a key)
app.post('/api/activate/issue', authMiddleware, async (req, res) => {
  try {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: 'deviceId가 필요합니다.' });

    const device = await db.devices.findById(deviceId);
    if (!device || device.user_id !== req.user.userId)
      return res.status(404).json({ error: '기기를 찾을 수 없습니다.' });

    const rawKey = crypto.randomBytes(8).toString('hex').toUpperCase();
    const formattedKey = rawKey.match(/.{1,4}/g).join('-');
    const keyHash = db.sha256(rawKey);
    const keyId = db.newId();
    const t = db.now();

    await db.activation.create({
      id: keyId,
      user_id: req.user.userId,
      device_id: deviceId,
      key_hash: keyHash,
      created_at: t,
      expires_at: t + ACTIVATION_TTL_MS,
    });

    res.json({
      activationKey: formattedKey,
      expiresAt: t + ACTIVATION_TTL_MS,
      message: '활성화 키가 발급되었습니다. 24시간 내에 사용하세요.',
    });
  } catch (e) {
    console.error('[activate-issue]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/activate/verify  (client verifies the key)
app.post('/api/activate/verify', async (req, res) => {
  try {
    const { activationKey, publicKey } = req.body;
    if (!activationKey || !publicKey)
      return res.status(400).json({ error: '활성화 키와 공개키가 필요합니다.' });

    const normalizedKey = activationKey.replace(/-|\s/g, '').toUpperCase();
    const keyHash = db.sha256(normalizedKey);
    const record = await db.activation.findValid(keyHash, db.now());

    if (!record) {
      return res.status(400).json({ error: '유효하지 않거나 만료된 활성화 키입니다.' });
    }

    const device = await db.devices.findById(record.device_id);
    if (!device || device.public_key !== publicKey) {
      return res.status(403).json({ error: '공개키가 등록된 기기와 일치하지 않습니다.' });
    }

    await db.activation.markUsed(record.id);
    await db.devices.updateLastSeen(db.now(), device.id);

    const user = await db.users.findById(record.user_id);
    const token = signToken({
      userId: user.id,
      username: user.username,
      deviceId: device.id,
      activated: true,
    });

    res.json({
      message: '활성화 완료! 클라이언트가 활성화되었습니다.',
      token,
      username: user.username,
      deviceId: device.id,
    });
  } catch (e) {
    console.error('[activate-verify]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ─────────────────────────────────────────────
// REST API - Rooms & Channels
// ─────────────────────────────────────────────

// POST /api/rooms
app.post('/api/rooms', authMiddleware, async (req, res) => {
  try {
    const { name, roomKeyHash, persistent } = req.body;
    if (!name || !roomKeyHash)
      return res.status(400).json({ error: '방 이름과 방 키 해시가 필요합니다.' });

    const existing = await db.rooms.findByKeyHash(roomKeyHash);
    if (existing) return res.status(409).json({ error: '이미 존재하는 방 키입니다.' });

    const roomSalt = crypto.randomBytes(16).toString('hex');
    const roomId = db.newId();
    const channelId = db.newId();
    const t = db.now();

    await db.rooms.create({
      id: roomId,
      room_key_hash: roomKeyHash,
      name,
      owner_user_id: req.user.userId,
      room_salt: roomSalt,
      persistent: persistent ? 1 : 0,
      created_at: t,
    });

    await db.channels.create({
      id: channelId,
      room_id: roomId,
      name: '일반',
      position: 0,
      created_at: t,
    });

    res.status(201).json({
      roomId,
      roomSalt,
      channels: [{ id: channelId, name: '일반', position: 0 }],
    });
  } catch (e) {
    console.error('[create-room]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/rooms/:keyHash
app.get('/api/rooms/:keyHash', authMiddleware, async (req, res) => {
  const room = await db.rooms.findByKeyHash(req.params.keyHash);
  if (!room) return res.status(404).json({ error: '방을 찾을 수 없습니다.' });

  const channels = await db.channels.listByRoom(room.id);
  res.json({
    roomId: room.id,
    name: room.name,
    roomSalt: room.room_salt,
    persistent: !!room.persistent,
    channels,
  });
});

// POST /api/rooms/:roomId/channels
app.post('/api/rooms/:roomId/channels', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: '채널 이름이 필요합니다.' });

    const room = await db.rooms.findById(req.params.roomId);
    if (!room) return res.status(404).json({ error: '방을 찾을 수 없습니다.' });

    const maxPosResult = await db.channels.maxPosition(room.id);
    const pos = maxPosResult ? maxPosResult.pos : -1;
    const channelId = db.newId();

    await db.channels.create({
      id: channelId,
      room_id: room.id,
      name,
      position: pos + 1,
      created_at: db.now(),
    });

    res.status(201).json({ channelId, name, position: pos + 1 });
  } catch (e) {
    console.error('[create-channel]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// DELETE /api/rooms/:roomId/channels/:channelId
app.delete('/api/rooms/:roomId/channels/:channelId', authMiddleware, async (req, res) => {
  await db.channels.delete(req.params.channelId, req.params.roomId);
  res.json({ message: '채널이 삭제되었습니다.' });
});

// ─────────────────────────────────────────────
// REST API - Persistent Messages
// ─────────────────────────────────────────────

// POST /api/messages (client pushes encrypted message for offline storage)
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { channelId, ciphertext, sentAt } = req.body;
    if (!channelId || !ciphertext)
      return res.status(400).json({ error: '채널 ID와 암호문이 필요합니다.' });

    const channel = await db.channels.findById(channelId);
    if (!channel) return res.status(404).json({ error: '채널을 찾을 수 없습니다.' });

    const room = await db.rooms.findById(channel.room_id);
    if (!room || !room.persistent)
      return res.status(400).json({ error: '이 방은 영구 저장이 비활성화되어 있습니다.' });

    const device = await db.devices.findById(req.user.deviceId || '');
    const senderKeyHash = device ? device.public_key_hash : db.sha256(req.user.userId);

    await db.messages.insert({
      id: db.newId(),
      channel_id: channelId,
      sender_key_hash: senderKeyHash,
      ciphertext,
      sent_at: sentAt || db.now(),
    });

    res.status(201).json({ message: '저장됨' });
  } catch (e) {
    console.error('[store-message]', e);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/messages/:channelId?after=timestamp
app.get('/api/messages/:channelId', authMiddleware, async (req, res) => {
  const after = parseInt(req.query.after) || 0;
  const channel = await db.channels.findById(req.params.channelId);
  if (!channel) return res.status(404).json({ error: '채널을 찾을 수 없습니다.' });

  const room = await db.rooms.findById(channel.room_id);
  if (!room || !room.persistent)
    return res.status(400).json({ error: '이 방은 영구 저장이 비활성화되어 있습니다.' });

  const messages = await db.messages.fetchAfter(req.params.channelId, after);
  res.json({ messages });
});

// ─────────────────────────────────────────────
// WebSocket Signaling Server
// ─────────────────────────────────────────────

// Map: roomId -> Set of clients in that room
const activeRooms = new Map();      // roomId -> Set<ws>
const clients = new Map();    // ws -> { userId, deviceId, username, publicKey, peerId, roomId, channelId }

function broadcast(roomId, message, excludeWs = null) {
  const roomClients = activeRooms.get(roomId);
  if (!roomClients) return;
  const data = JSON.stringify(message);
  for (const ws of roomClients) {
    if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  }
}

function send(ws, message) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

wss.on('connection', (ws) => {
  let authenticated = false;

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── Auth handshake ──────────────────────
    if (msg.type === 'auth') {
      const payload = verifyToken(msg.token);
      if (!payload) {
        send(ws, { type: 'auth_error', error: '인증 실패' });
        return ws.close();
      }
      authenticated = true;
      clients.set(ws, {
        userId: payload.userId,
        deviceId: payload.deviceId,
        username: payload.username,
        publicKey: msg.publicKey || '',
        peerId: msg.peerId || db.newId(),
        roomId: null,
        channelId: null,
      });
      await db.devices.updateLastSeen(db.now(), payload.deviceId || '');
      send(ws, { type: 'auth_ok', peerId: clients.get(ws).peerId });
      return;
    }

    if (!authenticated) return;
    const client = clients.get(ws);

    // ── Join Room ───────────────────────────
    if (msg.type === 'join_room') {
      const { roomKeyHash, channelId } = msg;
      const room = await db.rooms.findByKeyHash(roomKeyHash);
      if (!room) {
        send(ws, { type: 'error', error: '방을 찾을 수 없습니다.' });
        return;
      }

      if (client.roomId) {
        leaveRoom(ws, client);
      }

      client.roomId = room.id;
      client.channelId = channelId || null;

      if (!activeRooms.has(room.id)) activeRooms.set(room.id, new Set());
      const roomSet = activeRooms.get(room.id);

      const existingPeers = [];
      for (const ws2 of roomSet) {
        const c2 = clients.get(ws2);
        if (c2) existingPeers.push({
          peerId: c2.peerId,
          username: c2.username,
          publicKey: c2.publicKey,
        });
      }

      roomSet.add(ws);

      const channels = await db.channels.listByRoom(room.id);
      send(ws, {
        type: 'room_joined',
        roomId: room.id,
        roomName: room.name,
        roomSalt: room.room_salt,
        persistent: !!room.persistent,
        channels,
        peers: existingPeers,
      });

      broadcast(room.id, {
        type: 'peer_joined',
        peerId: client.peerId,
        username: client.username,
        publicKey: client.publicKey,
      }, ws);

      return;
    }

    // ── WebRTC Signal Relay ─────────────────
    if (msg.type === 'signal') {
      const { targetPeerId, payload } = msg;
      if (!client.roomId) return;

      const roomSet = activeRooms.get(client.roomId);
      if (!roomSet) return;
      for (const ws2 of roomSet) {
        const c2 = clients.get(ws2);
        if (c2 && c2.peerId === targetPeerId) {
          send(ws2, {
            type: 'signal',
            fromPeerId: client.peerId,
            payload,
          });
          break;
        }
      }
      return;
    }

    // ── Switch Channel ──────────────────────
    if (msg.type === 'switch_channel') {
      client.channelId = msg.channelId;
      return;
    }

    // ── Friend Request Relay ────────────────
    if (msg.type === 'friend_request') {
      const { targetPublicKeyHash, payload } = msg;
      for (const [ws2, c2] of clients) {
        if (db.sha256(c2.publicKey) === targetPublicKeyHash) {
          send(ws2, {
            type: 'friend_request',
            fromPeerId: client.peerId,
            fromUsername: client.username,
            fromPublicKey: client.publicKey,
            payload,
          });
          break;
        }
      }
      return;
    }

    // ── Persistent message push (offline cache) ─
    if (msg.type === 'store_message') {
      const { channelId, ciphertext, sentAt } = msg;
      const channel = await db.channels.findById(channelId);
      if (!channel) return;
      const room = await db.rooms.findById(channel.room_id);
      if (!room || !room.persistent) return;
      const device = await db.devices.findById(client.deviceId || '');
      const senderKeyHash = device ? device.public_key_hash : db.sha256(client.userId);
      await db.messages.insert({
        id: db.newId(),
        channel_id: channelId,
        sender_key_hash: senderKeyHash,
        ciphertext,
        sent_at: sentAt || db.now(),
      });
      return;
    }
  });

  ws.on('close', () => {
    const client = clients.get(ws);
    if (client) {
      leaveRoom(ws, client);
      clients.delete(ws);
    }
  });
});

function leaveRoom(ws, client) {
  if (!client.roomId) return;
  const roomSet = activeRooms.get(client.roomId);
  if (roomSet) {
    roomSet.delete(ws);
    if (roomSet.size === 0) activeRooms.delete(client.roomId);
    else {
      broadcast(client.roomId, {
        type: 'peer_left',
        peerId: client.peerId,
      }, ws);
    }
  }
  client.roomId = null;
  client.channelId = null;
}

// ─────────────────────────────────────────────
// Periodic Cleanup
// ─────────────────────────────────────────────
setInterval(async () => {
  try {
    const cutoff = Date.now() - MSG_RETENTION_MS;
    const result = await db.messages.purgeOld(cutoff);
    if (result && result.changes > 0) {
      console.log(`[cleanup] Purged ${result.changes} old messages`);
    }
  } catch (err) {
    console.error('[cleanup-error]', err);
  }
}, MSG_PURGE_INTERVAL_MS);

// ─────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────
async function startServer() {
  await db.init();
  server.listen(PORT, () => {
    console.log(`[TicMsg] Server listening on http://localhost:${PORT}`);
    console.log(`[TicMsg] WebSocket signaling ready`);
  });
}

startServer().catch(err => {
  console.error('[fatal-server-start-error]', err);
});
