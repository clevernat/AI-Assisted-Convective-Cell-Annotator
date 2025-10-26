-- Seed data for A-CLAT development and testing
-- Created: 2025-10-26

-- Insert test users
INSERT OR IGNORE INTO users (id, email, username, password_hash, full_name, role, api_key, is_active) VALUES 
  ('user_1', 'admin@aclat.com', 'admin', '$2a$10$XQq2o2D8.PQZ1F7H4yH6OuFwwJ9YqSa6R8oV6V0O5ZT0ChnJtBgVm', 'Admin User', 'admin', 'api_key_admin_123', 1),
  ('user_2', 'researcher@weather.edu', 'researcher1', '$2a$10$XQq2o2D8.PQZ1F7H4yH6OuFwwJ9YqSa6R8oV6V0O5ZT0ChnJtBgVm', 'Dr. Jane Smith', 'researcher', 'api_key_researcher_456', 1),
  ('user_3', 'user@example.com', 'weatherfan', '$2a$10$XQq2o2D8.PQZ1F7H4yH6OuFwwJ9YqSa6R8oV6V0O5ZT0ChnJtBgVm', 'John Doe', 'user', 'api_key_user_789', 1);

-- Insert test analyses
INSERT OR IGNORE INTO analyses (id, filename, variable, classification, confidence, justification, cells_data, statistics, processing_time_ms, file_size_bytes) VALUES 
  ('analysis_001', 'storm_20250726_1200.nc', 'Z', 'Supercell', 0.92, 
   'Supercell structure identified with maximum reflectivity of 68.5 dBZ and mesocyclone presence. VIL values reaching 65.2 kg/m² indicate significant hail potential.',
   '[{"id":"cell_1","peak_value":68.5,"lat":35.2,"lon":-97.4}]',
   '{"max_peak_dbz":68.5,"avg_peak_dbz":62.3,"max_vil_kg_m2":65.2}',
   2450, 15234567),
  
  ('analysis_002', 'mcs_20250725_1800.grib2', 'REFL', 'MCS', 0.88,
   'Mesoscale Convective System with 12 active cells showing organized structure.',
   '[{"id":"cell_1","peak_value":58.2,"lat":38.9,"lon":-94.6}]',
   '{"max_peak_dbz":58.2,"avg_peak_dbz":52.1,"max_vil_kg_m2":42.5}',
   3200, 28456789),
  
  ('analysis_003', 'squall_20250724_2100.nc', 'DBZ', 'Squall Line', 0.85,
   'Linear convective system detected with cells aligned along boundary.',
   '[{"id":"cell_1","peak_value":55.8,"lat":41.2,"lon":-88.3}]',
   '{"max_peak_dbz":55.8,"avg_peak_dbz":48.9,"max_vil_kg_m2":35.7}',
   1890, 9876543);

-- Insert test alerts
INSERT OR IGNORE INTO alerts (id, analysis_id, user_id, alert_type, severity, message, location_lat, location_lon, is_read) VALUES
  ('alert_001', 'analysis_001', 'user_2', 'tornado', 'extreme', 'Tornado warning: Supercell with strong rotation detected', 35.2, -97.4, 0),
  ('alert_002', 'analysis_001', 'user_3', 'hail', 'high', 'Large hail likely: MESH indicates 50mm+ hail possible', 35.2, -97.4, 1),
  ('alert_003', 'analysis_002', 'user_2', 'flood', 'high', 'Flash flood warning: Heavy rainfall from MCS', 38.9, -94.6, 0);

-- Insert test collaborations
INSERT OR IGNORE INTO collaborations (id, analysis_id, owner_user_id, shared_with_user_id, permission) VALUES
  ('collab_001', 'analysis_001', 'user_2', 'user_3', 'view'),
  ('collab_002', 'analysis_002', 'user_2', 'user_1', 'edit'),
  ('collab_003', 'analysis_003', 'user_1', 'user_2', 'admin');

-- Insert test exports
INSERT OR IGNORE INTO exports (id, analysis_id, user_id, format, file_size_bytes) VALUES
  ('export_001', 'analysis_001', 'user_2', 'csv', 45678),
  ('export_002', 'analysis_001', 'user_2', 'json', 123456),
  ('export_003', 'analysis_002', 'user_3', 'csv', 34567);

-- Insert test API usage
INSERT OR IGNORE INTO api_usage (id, user_id, endpoint, method, status_code, response_time_ms, ip_address) VALUES
  ('usage_001', 'user_2', '/api/analyze', 'POST', 200, 2450, '192.168.1.100'),
  ('usage_002', 'user_3', '/api/history', 'GET', 200, 125, '192.168.1.101'),
  ('usage_003', 'user_2', '/api/export', 'POST', 200, 890, '192.168.1.100');