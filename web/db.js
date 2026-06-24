/**
 * TicMsg Server - Database Schema & Initialization (sqlite/sqlite3 version)
 * All sensitive data stored as hashes only.
 */
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'ticmsg.db');
let dbInstance = null;

async function getDB() {
  if (dbInstance) return dbInstance;
  
  dbInstance = await open({
    filename: DB_PATH,
    driver: sqlite3.Database
  });

  // Enable WAL mode and foreign keys
  await dbInstance.run('PRAGMA journal_mode = WAL');
  await dbInstance.run('PRAGMA foreign_keys = ON');

  // Schema creation
  await dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      username    TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS devices (
      id              TEXT PRIMARY KEY,
      user_id         TEXT NOT NULL,
      public_key      TEXT NOT NULL,
      public_key_hash TEXT NOT NULL UNIQUE,
      device_name     TEXT DEFAULT '기기',
      registered_at   INTEGER NOT NULL,
      last_seen       INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS activation_keys (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL,
      device_id   TEXT NOT NULL,
      key_hash    TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL,
      is_used     INTEGER DEFAULT 0,
      FOREIGN KEY (user_id)  REFERENCES users(id)   ON DELETE CASCADE,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id              TEXT PRIMARY KEY,
      room_key_hash   TEXT UNIQUE NOT NULL,
      name            TEXT NOT NULL,
      owner_user_id   TEXT NOT NULL,
      room_salt       TEXT NOT NULL,
      persistent      INTEGER DEFAULT 0,
      created_at      INTEGER NOT NULL,
      FOREIGN KEY (owner_user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS channels (
      id          TEXT PRIMARY KEY,
      room_id     TEXT NOT NULL,
      name        TEXT NOT NULL,
      position    INTEGER DEFAULT 0,
      created_at  INTEGER NOT NULL,
      FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id              TEXT PRIMARY KEY,
      channel_id      TEXT NOT NULL,
      sender_key_hash TEXT NOT NULL,
      ciphertext      TEXT NOT NULL,
      sent_at         INTEGER NOT NULL,
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_devices_user   ON devices(user_id);
    CREATE INDEX IF NOT EXISTS idx_devices_keyhash ON devices(public_key_hash);
    CREATE INDEX IF NOT EXISTS idx_channels_room  ON channels(room_id);
    CREATE INDEX IF NOT EXISTS idx_messages_chan  ON messages(channel_id, sent_at);
    CREATE INDEX IF NOT EXISTS idx_actkeys_device ON activation_keys(device_id);
  `);

  return dbInstance;
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function newId() {
  return crypto.randomUUID();
}

function now() {
  return Date.now();
}

// ─────────────────────────────────────────────
// Queries (Async wrapper mapping better-sqlite3 patterns to sqlite/sqlite3)
// ─────────────────────────────────────────────
const userQueries = {
  async create({ id, username, password_hash, created_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO users (id, username, password_hash, created_at)
       VALUES (?, ?, ?, ?)`,
      [id, username, password_hash, created_at]
    );
  },
  async findByUsername(username) {
    const db = await getDB();
    return db.get(`SELECT * FROM users WHERE username = ?`, [username]);
  },
  async findById(id) {
    const db = await getDB();
    return db.get(`SELECT * FROM users WHERE id = ?`, [id]);
  }
};

const deviceQueries = {
  async create({ id, user_id, public_key, public_key_hash, device_name, registered_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO devices (id, user_id, public_key, public_key_hash, device_name, registered_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [id, user_id, public_key, public_key_hash, device_name, registered_at]
    );
  },
  async countByUser(userId) {
    const db = await getDB();
    return db.get(`SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?`, [userId]);
  },
  async listByUser(userId) {
    const db = await getDB();
    return db.all(
      `SELECT id, device_name, public_key_hash, registered_at, last_seen
       FROM devices WHERE user_id = ? ORDER BY registered_at ASC`,
      [userId]
    );
  },
  async findById(id) {
    const db = await getDB();
    return db.get(`SELECT * FROM devices WHERE id = ?`, [id]);
  },
  async findByKeyHash(publicKeyHash) {
    const db = await getDB();
    return db.get(`SELECT * FROM devices WHERE public_key_hash = ?`, [publicKeyHash]);
  },
  async delete(id, userId) {
    const db = await getDB();
    return db.run(`DELETE FROM devices WHERE id = ? AND user_id = ?`, [id, userId]);
  },
  async updateLastSeen(timestamp, id) {
    const db = await getDB();
    return db.run(`UPDATE devices SET last_seen = ? WHERE id = ?`, [timestamp, id]);
  }
};

const activationQueries = {
  async create({ id, user_id, device_id, key_hash, created_at, expires_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO activation_keys (id, user_id, device_id, key_hash, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [id, user_id, device_id, key_hash, created_at, expires_at]
    );
  },
  async findValid(keyHash, currentTime) {
    const db = await getDB();
    return db.get(
      `SELECT * FROM activation_keys
       WHERE key_hash = ? AND is_used = 0 AND expires_at > ?`,
      [keyHash, currentTime]
    );
  },
  async markUsed(id) {
    const db = await getDB();
    return db.run(`UPDATE activation_keys SET is_used = 1 WHERE id = ?`, [id]);
  },
  async listByDevice(deviceId) {
    const db = await getDB();
    return db.all(
      `SELECT * FROM activation_keys WHERE device_id = ? ORDER BY created_at DESC LIMIT 5`,
      [deviceId]
    );
  }
};

const roomQueries = {
  async create({ id, room_key_hash, name, owner_user_id, room_salt, persistent, created_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO rooms (id, room_key_hash, name, owner_user_id, room_salt, persistent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [id, room_key_hash, name, owner_user_id, room_salt, persistent, created_at]
    );
  },
  async findByKeyHash(roomKeyHash) {
    const db = await getDB();
    return db.get(`SELECT * FROM rooms WHERE room_key_hash = ?`, [roomKeyHash]);
  },
  async findById(id) {
    const db = await getDB();
    return db.get(`SELECT * FROM rooms WHERE id = ?`, [id]);
  },
  async updatePersistent(persistent, id) {
    const db = await getDB();
    return db.run(`UPDATE rooms SET persistent = ? WHERE id = ?`, [persistent, id]);
  }
};

const channelQueries = {
  async create({ id, room_id, name, position, created_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO channels (id, room_id, name, position, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [id, room_id, name, position, created_at]
    );
  },
  async listByRoom(roomId) {
    const db = await getDB();
    return db.all(`SELECT * FROM channels WHERE room_id = ? ORDER BY position ASC`, [roomId]);
  },
  async findById(id) {
    const db = await getDB();
    return db.get(`SELECT * FROM channels WHERE id = ?`, [id]);
  },
  async delete(id, roomId) {
    const db = await getDB();
    return db.run(`DELETE FROM channels WHERE id = ? AND room_id = ?`, [id, roomId]);
  },
  async maxPosition(roomId) {
    const db = await getDB();
    return db.get(`SELECT COALESCE(MAX(position), -1) as pos FROM channels WHERE room_id = ?`, [roomId]);
  }
};

const messageQueries = {
  async insert({ id, channel_id, sender_key_hash, ciphertext, sent_at }) {
    const db = await getDB();
    return db.run(
      `INSERT INTO messages (id, channel_id, sender_key_hash, ciphertext, sent_at)
       VALUES (?, ?, ?, ?, ?)`,
      [id, channel_id, sender_key_hash, ciphertext, sent_at]
    );
  },
  async fetchAfter(channelId, afterTimestamp) {
    const db = await getDB();
    return db.all(
      `SELECT * FROM messages WHERE channel_id = ? AND sent_at > ?
       ORDER BY sent_at ASC LIMIT 500`,
      [channelId, afterTimestamp]
    );
  },
  async purgeOld(cutoffTimestamp) {
    const db = await getDB();
    return db.run(`DELETE FROM messages WHERE sent_at < ?`, [cutoffTimestamp]);
  }
};

module.exports = {
  init: getDB, // Expose initialization function
  sha256, newId, now,
  users: userQueries,
  devices: deviceQueries,
  activation: activationQueries,
  rooms: roomQueries,
  channels: channelQueries,
  messages: messageQueries,
};
