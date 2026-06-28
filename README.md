# TicMsg v2 — 완전 서버리스 E2EE P2P 메신저

## 핵심 특징

- **백엔드 인증 서버 불필요** — 로컬 신원, 방 코드 기반
- **키 정보 직접 공유 불필요** — 방 코드 하나로 그룹키 자동 파생
- **그리드넷 P2P** — WebRTC DataChannel 직접 통신 (서버 미거침)
- **SPAKE2-lite 상호 인증** — 방 코드 충돌에도 다른 그룹 메시지 열람 불가
- **E2EE** — AES-GCM-256 + ECDH P-256 + HKDF 채널 분리

## 아키텍처

```
방 코드 (예: "apple-river-7341")
  ├─ PBKDF2(200K) → 그룹 암호키
  ├─ HMAC-SHA256  → roomSalt (채널키 분리용)
  └─ SHA-256      → roomId  (시그널링 서버 식별자, 공개)

시그널링 (선택):
  ① 이 서버 (web/server.js) — 순수 WebRTC 중계만, 인증/DB 없음
  ② PeerJS 공개 브로커     — 코드만, 서버 운영 불필요
  ③ 수동 교환 (QR/텍스트)  — 완전 오프라인

채팅:
  WebRTC DataChannel (E2EE, 서버 미거침)
  gossip broadcast + msgId 중복 방지
```

## 시그널링 서버 실행 (선택)

```bash
cd web
npm install
npm start   # ws://localhost:3000
```

## 보안 요약

| 공격자가 아는 것 | 공격자가 모르는 것 |
|---|---|
| roomId (공개 해시) | 방 코드 (PBKDF2 200K) |
| 암호화된 메시지 | 메시지 내용 (AES-GCM-256) |
| 피어의 공개키 | 피어의 개인키 |
| 시그널링 SDP | 채널 키 (HKDF 로컬 파생) |

서버가 해킹되거나 꺼져도 채팅 내용 복호화 불가.

## v1 → v2 주요 변경

- `auth.js`: JWT/서버인증 → LocalIdentity (로컬 전용)
- `crypto.js`: roomSalt 서버 수신 → 로컬 결정론적 파생, 방 코드 생성 추가
- `p2p.js`: SPAKE2-lite 상호 인증, gossip msgId 중복 방지, 파일 청크 버그 수정
- `signal.js`: JWT/활성화 → 순수 WebRTC 중계 프로토콜
- `signal_serverless.js`: PeerJS 브로커 + 수동 교환 모드 (NEW)
- `web/server.js`: 667줄 → 100줄 (인증/DB/REST 전부 제거)
- `web/db.js`: 삭제
- `web/public/`: 삭제 (웹 관리 패널 제거)
