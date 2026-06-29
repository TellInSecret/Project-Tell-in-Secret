/**
 * TicMsg v2 - 경량 WebRTC 시그널링 서버 (선택적)
 *
 * 이 서버는 선택 사항입니다.
 * 클라이언트는 PeerJS 공개 브로커 또는 수동 교환으로도 동작합니다.
 *
 * 역할:
 *  - WebRTC SDP/ICE 중계만 담당
 *  - 인증 없음, DB 없음, 메모리만 사용
 *  - 방 식별: roomId = SHA-256(방코드) → 클라이언트가 계산해서 전달
 *  - 서버는 roomId만 알고 방코드(비밀)는 절대 전달받지 않음
 *
 * 보안:
 *  - 서버가 SDP를 볼 수 있지만 실제 채팅 내용은 DataChannel로만 전송
 *  - 서버가 해킹당해도 채팅 내용 열람 불가 (E2EE DataChannel)
 *  - 피어 인증은 클라이언트 SPAKE2-lite로 수행 (서버 무관)
 *
 * 실행: node server.js
 * 환경변수:
 *   PORT (기본 3000)
 *   HOST (기본 0.0.0.0 - 모든 네트워크 인터페이스에서 수신 → LAN/외부 접속 허용)
 *        localhost 전용으로 제한하려면 HOST=127.0.0.1 설정
 */

const http      = require('http');
const WebSocket = require('ws');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('TicMsg v2 Signaling Server\n');
});

const wss = new WebSocket.Server({ server });

// roomId -> Set<ws>
const rooms = new Map();
// ws -> { peerId, roomId, username, publicKey }
const clients = new Map();

function send(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function broadcast(roomId, obj, excludeWs = null) {
  const room = rooms.get(roomId);
  if (!room) return;
  const data = JSON.stringify(obj);
  for (const ws of room) {
    if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  }
}

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── 입장 ────────────────────────────────────────
    if (msg.type === 'join') {
      const { roomId, peerId, username, publicKey } = msg;
      if (!roomId || !peerId) return;

      // 기존 방 퇴장
      const existing = clients.get(ws);
      if (existing?.roomId) leaveRoom(ws, existing);

      const client = { peerId, roomId, username: username || '사용자', publicKey: publicKey || '' };
      clients.set(ws, client);

      if (!rooms.has(roomId)) rooms.set(roomId, new Set());
      const room = rooms.get(roomId);

      // 기존 피어 목록 전송
      const peers = [];
      for (const ws2 of room) {
        const c2 = clients.get(ws2);
        if (c2) peers.push({ peerId: c2.peerId, username: c2.username, publicKey: c2.publicKey });
      }

      room.add(ws);

      send(ws, { type: 'joined', peerId, peers });

      // 기존 피어들에게 새 피어 알림
      broadcast(roomId, {
        type: 'peer_joined',
        peerId,
        username: client.username,
        publicKey: client.publicKey,
      }, ws);

      return;
    }

    const client = clients.get(ws);
    if (!client) return;

    // ── WebRTC 시그널 중계 ───────────────────────────
    if (msg.type === 'signal') {
      const { targetPeerId, payload } = msg;
      if (!client.roomId) return;

      const room = rooms.get(client.roomId);
      if (!room) return;

      for (const ws2 of room) {
        const c2 = clients.get(ws2);
        if (c2 && c2.peerId === targetPeerId) {
          send(ws2, { type: 'signal', fromPeerId: client.peerId, payload });
          break;
        }
      }
      return;
    }

    // ── 퇴장 ────────────────────────────────────────
    if (msg.type === 'leave') {
      leaveRoom(ws, client);
      return;
    }
  });

  ws.on('close', () => {
    const client = clients.get(ws);
    if (client) leaveRoom(ws, client);
    clients.delete(ws);
  });
});

function leaveRoom(ws, client) {
  if (!client.roomId) return;
  const room = rooms.get(client.roomId);
  if (room) {
    room.delete(ws);
    if (room.size === 0) {
      rooms.delete(client.roomId);
    } else {
      broadcast(client.roomId, { type: 'peer_left', peerId: client.peerId });
    }
  }
  client.roomId = null;
}

const HOST = process.env.HOST || '0.0.0.0';
server.listen(PORT, HOST, () => {
  console.log(`[TicMsg v2] Signaling server listening on ${HOST}:${PORT}`);
  console.log(`[TicMsg v2] Local:   ws://localhost:${PORT}`);
  console.log(`[TicMsg v2] Network: ws://<this-machine-ip>:${PORT} (LAN/외부 접속용)`);
  console.log(`[TicMsg v2] No auth, no DB - pure WebRTC relay only`);
});
