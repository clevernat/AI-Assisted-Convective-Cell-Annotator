-- Initial schema for A-CLAT application
-- Created: 2025-10-26

-- Main analyses table for storing processing results
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  variable TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  justification TEXT,
  cells_data TEXT, -- JSON string containing cell data
  hazards TEXT, -- JSON array of hazard types
  statistics TEXT, -- JSON object with analysis statistics
  processing_time_ms INTEGER,
  file_size_bytes INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Users table for authentication (future implementation)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'researcher')),
  api_key TEXT UNIQUE,
  is_active BOOLEAN DEFAULT 1,
  last_login DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table for user sessions
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Alerts table for notification system
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL,
  user_id TEXT,
  alert_type TEXT NOT NULL CHECK (alert_type IN ('tornado', 'hail', 'wind', 'flood', 'general')),
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'extreme')),
  message TEXT NOT NULL,
  location_lat REAL,
  location_lon REAL,
  is_read BOOLEAN DEFAULT 0,
  sent_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Collaborations table for shared analyses
CREATE TABLE IF NOT EXISTS collaborations (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  shared_with_user_id TEXT NOT NULL,
  permission TEXT DEFAULT 'view' CHECK (permission IN ('view', 'edit', 'admin')),
  shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
  FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(analysis_id, owner_user_id, shared_with_user_id)
);

-- Export history table
CREATE TABLE IF NOT EXISTS exports (
  id TEXT PRIMARY KEY,
  analysis_id TEXT NOT NULL,
  user_id TEXT,
  format TEXT NOT NULL CHECK (format IN ('csv', 'json', 'netcdf', 'geojson')),
  file_path TEXT,
  file_size_bytes INTEGER,
  exported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- API usage tracking
CREATE TABLE IF NOT EXISTS api_usage (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  request_body_size INTEGER,
  response_body_size INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_classification ON analyses(classification);
CREATE INDEX IF NOT EXISTS idx_analyses_confidence ON analyses(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_filename ON analyses(filename);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_alerts_analysis_id ON alerts(analysis_id);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_is_read ON alerts(is_read);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE INDEX IF NOT EXISTS idx_collaborations_analysis_id ON collaborations(analysis_id);
CREATE INDEX IF NOT EXISTS idx_collaborations_owner_user_id ON collaborations(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_collaborations_shared_with_user_id ON collaborations(shared_with_user_id);

CREATE INDEX IF NOT EXISTS idx_exports_analysis_id ON exports(analysis_id);
CREATE INDEX IF NOT EXISTS idx_exports_user_id ON exports(user_id);

CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage(endpoint);
CREATE INDEX IF NOT EXISTS idx_api_usage_created_at ON api_usage(created_at DESC);

-- Add triggers for updated_at timestamps
-- Note: SQLite doesn't support CREATE OR REPLACE TRIGGER, so we drop first if exists
DROP TRIGGER IF EXISTS update_analyses_updated_at;
CREATE TRIGGER update_analyses_updated_at
AFTER UPDATE ON analyses
BEGIN
  UPDATE analyses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

DROP TRIGGER IF EXISTS update_users_updated_at;
CREATE TRIGGER update_users_updated_at
AFTER UPDATE ON users
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;