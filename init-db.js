import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';

dotenv.config();

const db = new Database(process.env.DB_PATH || './database.sqlite');

console.log('🔧 Initializing database...');

// Enable foreign keys
db.pragma('foreign_keys = ON');

// ============= TABLES =============

// Users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    has_private_access BOOLEAN DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    CONSTRAINT username_length CHECK (length(username) >= 3 AND length(username) <= 50),
    CONSTRAINT email_format CHECK (email LIKE '%@%')
  )
`);

// Sessions table
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// Threads table
db.exec(`
  CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    is_private BOOLEAN DEFAULT 0,
    views INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT title_length CHECK (length(title) >= 5 AND length(title) <= 200),
    CONSTRAINT body_length CHECK (length(body) >= 10 AND length(body) <= 5000)
  )
`);

// Replies table
db.exec(`
  CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT text_length CHECK (length(text) >= 5 AND length(text) <= 2000)
  )
`);

// Access Keys table (для доступа к приватным темам)
db.exec(`
  CREATE TABLE IF NOT EXISTS access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_by INTEGER NOT NULL,
    used_by INTEGER,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (used_by) REFERENCES users(id)
  )
`);

// SIEM Events table
db.exec(`
  CREATE TABLE IF NOT EXISTS siem_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// ============= INDEXES =============

db.exec(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_threads_author ON threads(author_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_threads_created ON threads(created_at DESC)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_replies_thread ON replies(thread_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_replies_author ON replies(author_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_access_keys_code ON access_keys(key_code)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_siem_events_created ON siem_events(created_at DESC)`);

console.log('✅ Tables and indexes created');

// ============= SEED ADMIN USER =============

const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
const adminEmail = process.env.ADMIN_EMAIL || 'admin@offensive-forum.local';

// Check if admin exists
const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get(adminUsername);

if (!existingAdmin) {
  const passwordHash = bcrypt.hashSync(adminPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  
  db.prepare(`
    INSERT INTO users (username, email, password_hash, is_admin, has_private_access, created_at)
    VALUES (?, ?, ?, 1, 1, ?)
  `).run(adminUsername, adminEmail, passwordHash, Date.now());
  
  console.log(`✅ Admin user created:`);
  console.log(`   Username: ${adminUsername}`);
  console.log(`   Password: ${adminPassword}`);
  console.log(`   ⚠️  CHANGE THE PASSWORD IMMEDIATELY!`);
} else {
  console.log('ℹ️  Admin user already exists');
}

// ============= SEED SAMPLE DATA (optional) =============

const threadCount = db.prepare('SELECT COUNT(*) as count FROM threads').get().count;

if (threadCount === 0) {
  console.log('📝 Creating sample threads...');
  
  const adminId = db.prepare('SELECT id FROM users WHERE username = ?').get(adminUsername).id;
  
  // Public thread
  db.prepare(`
    INSERT INTO threads (title, body, author_id, is_private, created_at, updated_at)
    VALUES (?, ?, ?, 0, ?, ?)
  `).run(
    'Welcome to offensive-forum',
    'This is the first public thread. Everyone can see this!',
    adminId,
    Date.now(),
    Date.now()
  );
  
  // Private thread (только для админов и юзеров с ключом)
  db.prepare(`
    INSERT INTO threads (title, body, author_id, is_private, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `).run(
    'Private: Advanced Security Topics',
    'This thread is private and only visible to users with special access keys.',
    adminId,
    Date.now(),
    Date.now()
  );
  
  console.log('✅ Sample threads created');
}

// ============= GENERATE SAMPLE ACCESS KEY =============

const keyCount = db.prepare('SELECT COUNT(*) as count FROM access_keys').get().count;

if (keyCount === 0) {
  console.log('🔑 Generating sample access key...');
  
  const adminId = db.prepare('SELECT id FROM users WHERE username = ?').get(adminUsername).id;
  const sampleKey = generateAccessKey();
  
  db.prepare(`
    INSERT INTO access_keys (key_code, created_by, created_at)
    VALUES (?, ?, ?)
  `).run(sampleKey, adminId, Date.now());
  
  console.log(`✅ Sample access key: ${sampleKey}`);
  console.log(`   Use this key to access private threads!`);
}

db.close();

console.log('🎉 Database initialization complete!');
console.log('');
console.log('🚀 Next steps:');
console.log('   1. npm install');
console.log('   2. npm start');
console.log('   3. Open http://localhost:3000');

// ============= HELPER FUNCTIONS =============

function generateAccessKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const parts = [];
  
  for (let i = 0; i < 4; i++) {
    let part = '';
    for (let j = 0; j < 4; j++) {
      part += chars[Math.floor(Math.random() * chars.length)];
    }
    parts.push(part);
  }
  
  return parts.join('-');
}
