# 프로젝트 개요
백엔드 인증 서버 없이 동작하는 E2EE P2P 메신저입니다. Tauri(Rust 데스크탑 쉘) + 바닐라 JS 프론트엔드 구조이며, WebRTC DataChannel로 클라이언트끼리 직접 통신합니다.

## 핵심 설계 방향

방 코드 (예: "apple-river-7341")  ← 자동 생성, 사용자끼리 공유
  ├─ HMAC-SHA256 → roomSalt       (로컬 파생, 서버 불필요)
  ├─ SHA-256     → roomId         (시그널링 서버 식별자, 공개)
  └─ PBKDF2 200K → 그룹키         (AES-GCM-256)
       └─ HKDF(roomSalt) → 채널별 독립키
       
## 파일 구성 (클라이언트 JS)

파일        역 할
crypto.js    암호 원시함수 전체 (ECDH, AES-GCM, PBKDF2, HKDF, 방 코드 생성)
p2p.js    그리드넷 메시 매니저 — WebRTC 연결, 상호 인증, gossip 브로드캐스트
signal.js    WebSocket 시그널링 클라이언트 (자체 서버용)
signal_serverless.js    PeerJS 브로커 또는 QR/텍스트 수동 교환 모드
friendcode.js    Base58 친구 코드, SDP 압축, challenge-response 헬퍼
auth.js    로컬 신원 관리만 (JWT/서버 인증 완전 제거)

## 보안 포인트

DataChannel 연결 직후 SPAKE2-lite 상호 인증을 수행합니다. 우연히 같은 방 코드를 쓰는 다른 그룹이 있더라도, ECDH 공개키가 달라 sharedKey가 달라지므로 인증 단계에서 자동으로 걸러집니다. 또한 gossip 메시지에 msgId를 부여해 중복 수신을 방지하고 있습니다.

시그널링은 세 가지 방식을 지원합니다 — ① 자체 경량 서버(ws만 의존, ~100줄), ② PeerJS 공개 브로커, ③ 완전 오프라인 수동 교환. 어떤 방식을 쓰더라도 서버에는 roomId(SHA-256 해시)만 노출되고 방 코드 원문이나 채팅 내용은 절대 전달되지 않습니다.

-# 주 개발: lubram
