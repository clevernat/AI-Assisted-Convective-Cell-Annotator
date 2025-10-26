-- Simple seed data for testing
INSERT OR IGNORE INTO users (id, email, username, password_hash, full_name, role, is_active) VALUES 
  ('user_1', 'test@example.com', 'testuser', 'hashed_password', 'Test User', 'user', 1),
  ('user_2', 'admin@aclat.com', 'admin', 'hashed_password', 'Admin User', 'admin', 1);