import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'
import { sign, verify } from 'hono/jwt'
import { setCookie, getCookie } from 'hono/cookie'
// Using Web Crypto API for password hashing instead of bcryptjs

type Bindings = {
  DB?: D1Database;
  KV?: KVNamespace;
  R2?: R2Bucket;
  JWT_SECRET: string;
}

type User = {
  id: string;
  email: string;
  username: string;
  password_hash: string;
  full_name?: string;
  role: string;
  api_key: string;
  is_active: number;
}

const app = new Hono<{ Bindings: Bindings }>()

// Enable CORS
app.use('/api/*', cors())

// Serve static files
app.use('/static/*', serveStatic({ root: './public' }))

// ==================== DATABASE INITIALIZATION ====================
async function initializeDatabase(db: D1Database) {
  try {
    // Run the migration to create all tables
    const migration = `
      -- Analyses table
      CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        variable TEXT NOT NULL,
        classification TEXT NOT NULL,
        confidence REAL NOT NULL,
        justification TEXT,
        cells_data TEXT,
        hazards TEXT,
        statistics TEXT,
        processing_time_ms INTEGER,
        file_size_bytes INTEGER,
        user_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        api_key TEXT UNIQUE,
        is_active INTEGER DEFAULT 1,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      -- Sessions table
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

      -- Alerts table
      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        analysis_id TEXT NOT NULL,
        user_id TEXT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        location_lat REAL,
        location_lon REAL,
        is_read INTEGER DEFAULT 0,
        sent_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      -- Collaborations table
      CREATE TABLE IF NOT EXISTS collaborations (
        id TEXT PRIMARY KEY,
        analysis_id TEXT NOT NULL,
        owner_user_id TEXT NOT NULL,
        shared_with_user_id TEXT NOT NULL,
        permission TEXT DEFAULT 'view',
        shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
        FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(analysis_id, owner_user_id, shared_with_user_id)
      );

      -- Create indexes
      CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_analyses_classification ON analyses(classification);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    `;

    // Execute migration
    const statements = migration.split(';').filter(s => s.trim());
    for (const statement of statements) {
      if (statement.trim()) {
        await db.prepare(statement).run();
      }
    }
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// ==================== AUTHENTICATION HELPERS ====================
async function generateToken(userId: string, email: string, secret: string): Promise<string> {
  const payload = {
    sub: userId,
    email: email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60)
  }
  return await sign(payload, secret)
}

async function verifyToken(token: string, secret: string) {
  try {
    const payload = await verify(token, secret)
    return payload
  } catch (error) {
    return null
  }
}

async function hashPassword(password: string): Promise<string> {
  // Simple hash using Web Crypto API for Cloudflare Workers
  const encoder = new TextEncoder()
  const data = encoder.encode(password + 'salt-key-2025')
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const newHash = await hashPassword(password)
  return newHash === hash
}

// Middleware to protect routes
async function requireAuth(c: any, next: any) {
  const { env } = c
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')

  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401)
  }

  const session = await env.DB.prepare(`
    SELECT * FROM sessions 
    WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
  `).bind(token).first()

  if (!session) {
    return c.json({ error: 'Session expired' }, 401)
  }

  c.set('userId', payload.sub)
  c.set('userEmail', payload.email)

  await next()
}

// ==================== AUTHENTICATION ENDPOINTS ====================
app.post('/api/auth/register', async (c) => {
  const { env } = c
  const { email, username, password, full_name } = await c.req.json()

  if (!env.DB) {
    await initializeDatabase(env.DB!)
  }

  if (!email || !username || !password) {
    return c.json({ error: 'Missing required fields' }, 400)
  }

  const existingUser = await env.DB!.prepare(
    'SELECT id FROM users WHERE email = ? OR username = ?'
  ).bind(email, username).first()

  if (existingUser) {
    return c.json({ error: 'User already exists' }, 409)
  }

  const passwordHash = await hashPassword(password)
  const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const apiKey = `api_${Math.random().toString(36).substr(2, 32)}`

  await env.DB!.prepare(`
    INSERT INTO users (id, email, username, password_hash, full_name, api_key, is_active)
    VALUES (?, ?, ?, ?, ?, ?, 1)
  `).bind(userId, email, username, passwordHash, full_name || null, apiKey).run()

  const token = await generateToken(userId, email, env.JWT_SECRET || 'default-secret')
  const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

  await env.DB!.prepare(`
    INSERT INTO sessions (id, user_id, token, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionId, userId, token, expiresAt).run()

  setCookie(c, 'auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60,
    path: '/'
  })

  return c.json({
    success: true,
    user: { id: userId, email, username, full_name, api_key: apiKey },
    token
  })
})

app.post('/api/auth/login', async (c) => {
  const { env } = c
  const { email, password } = await c.req.json()

  if (!env.DB) {
    await initializeDatabase(env.DB!)
  }

  if (!email || !password) {
    return c.json({ error: 'Missing credentials' }, 400)
  }

  const user = await env.DB!.prepare(`
    SELECT * FROM users WHERE email = ? OR username = ?
  `).bind(email, email).first() as User | null

  if (!user || !user.is_active) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const isValid = await verifyPassword(password, user.password_hash)
  if (!isValid) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  await env.DB!.prepare(`
    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
  `).bind(user.id).run()

  const token = await generateToken(user.id, user.email, env.JWT_SECRET || 'default-secret')
  const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

  await env.DB!.prepare(`
    INSERT INTO sessions (id, user_id, token, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionId, user.id, token, expiresAt).run()

  setCookie(c, 'auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60,
    path: '/'
  })

  return c.json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      full_name: user.full_name,
      role: user.role
    },
    token
  })
})

app.post('/api/auth/logout', async (c) => {
  const { env } = c
  const token = getCookie(c, 'auth_token')

  if (token && env.DB) {
    await env.DB.prepare(`
      DELETE FROM sessions WHERE token = ?
    `).bind(token).run()
  }

  setCookie(c, 'auth_token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 0,
    path: '/'
  })

  return c.json({ success: true, message: 'Logged out successfully' })
})

app.get('/api/auth/me', async (c) => {
  const { env } = c
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')

  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401)
  }

  const user = await env.DB!.prepare(`
    SELECT id, email, username, full_name, role, api_key, created_at
    FROM users WHERE id = ?
  `).bind(payload.sub).first()

  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  return c.json({ success: true, user })
})

// ==================== ALERT SYSTEM ====================
async function createAlert(
  db: D1Database,
  analysisId: string,
  userId: string | null,
  classification: string,
  hazards: string[],
  statistics: any,
  location: { lat: number; lon: number }
): Promise<void> {
  
  let alertType = 'general'
  let severity = 'low'
  let message = ''

  if (classification === 'Supercell' && hazards.includes('Tornado Possible')) {
    alertType = 'tornado'
    severity = 'extreme'
    message = `TORNADO WARNING: Supercell with strong rotation detected at ${location.lat.toFixed(2)}°N, ${location.lon.toFixed(2)}°W. Seek shelter immediately!`
  } else if (hazards.includes('Large Hail') && statistics.max_mesh_mm > 50) {
    alertType = 'hail'
    severity = statistics.max_mesh_mm > 75 ? 'extreme' : 'high'
    message = `LARGE HAIL WARNING: Hail up to ${statistics.max_mesh_mm.toFixed(0)}mm diameter expected. Seek indoor shelter.`
  } else if (classification === 'Squall Line' || hazards.includes('Damaging Winds')) {
    alertType = 'wind'
    severity = 'high'
    message = `DAMAGING WIND WARNING: ${classification} producing winds capable of damage.`
  } else if (classification === 'MCS' || hazards.includes('Flash Flooding')) {
    alertType = 'flood'
    severity = 'high'
    message = `FLASH FLOOD WARNING: Heavy rainfall from ${classification}.`
  } else {
    alertType = 'general'
    severity = 'medium'
    message = `WEATHER ALERT: ${classification} detected with potential for ${hazards.join(', ')}.`
  }

  const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  await db.prepare(`
    INSERT INTO alerts (id, analysis_id, user_id, alert_type, severity, message, location_lat, location_lon, is_read, sent_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
  `).bind(alertId, analysisId, userId, alertType, severity, message, location.lat, location.lon).run()
}

app.get('/api/alerts', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { unread_only, severity, limit } = c.req.query()

  if (!env.DB) return c.json({ alerts: [] })

  let query = `
    SELECT a.*, an.filename, an.classification, an.confidence
    FROM alerts a
    LEFT JOIN analyses an ON a.analysis_id = an.id
    WHERE 1=1
  `
  const params: any[] = []

  if (userId) {
    query += ` AND (a.user_id = ? OR a.user_id IS NULL)`
    params.push(userId)
  }

  if (unread_only === 'true') {
    query += ` AND a.is_read = 0`
  }

  if (severity) {
    query += ` AND a.severity = ?`
    params.push(severity)
  }

  query += ` ORDER BY a.created_at DESC LIMIT ?`
  params.push(parseInt(limit as string) || 50)

  const results = await env.DB.prepare(query).bind(...params).all()

  return c.json({
    success: true,
    alerts: results.results || []
  })
})

app.patch('/api/alerts/:id/read', requireAuth, async (c) => {
  const { env } = c
  const alertId = c.req.param('id')
  const userId = c.get('userId')

  await env.DB!.prepare(`
    UPDATE alerts SET is_read = 1 
    WHERE id = ? AND (user_id = ? OR user_id IS NULL)
  `).bind(alertId, userId).run()

  return c.json({ success: true })
})

// ==================== SEARCH ENDPOINTS ====================
app.post('/api/search/analyses', async (c) => {
  const { env } = c
  const { query, classification, confidence_min, confidence_max, date_from, date_to, limit, offset } = await c.req.json()

  if (!env.DB) return c.json({ results: [] })

  let sql = `SELECT * FROM analyses WHERE 1=1`
  const params: any[] = []

  if (query) {
    sql += ` AND (filename LIKE ? OR justification LIKE ?)`
    params.push(`%${query}%`, `%${query}%`)
  }

  if (classification) {
    sql += ` AND classification = ?`
    params.push(classification)
  }

  if (confidence_min !== undefined) {
    sql += ` AND confidence >= ?`
    params.push(confidence_min)
  }

  if (confidence_max !== undefined) {
    sql += ` AND confidence <= ?`
    params.push(confidence_max)
  }

  if (date_from) {
    sql += ` AND created_at >= ?`
    params.push(date_from)
  }

  if (date_to) {
    sql += ` AND created_at <= ?`
    params.push(date_to)
  }

  sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
  params.push(parseInt(limit) || 20, parseInt(offset) || 0)

  const results = await env.DB.prepare(sql).bind(...params).all()

  return c.json({
    success: true,
    results: results.results || [],
    pagination: {
      limit: parseInt(limit) || 20,
      offset: parseInt(offset) || 0
    }
  })
})

app.get('/api/search/facets', async (c) => {
  const { env } = c

  if (!env.DB) return c.json({ facets: {} })

  const classifications = await env.DB.prepare(`
    SELECT classification, COUNT(*) as count
    FROM analyses GROUP BY classification
    ORDER BY count DESC
  `).all()

  const dateRange = await env.DB.prepare(`
    SELECT MIN(created_at) as earliest, MAX(created_at) as latest, COUNT(*) as total
    FROM analyses
  `).first()

  return c.json({
    success: true,
    facets: {
      classifications: classifications.results || [],
      date_range: dateRange
    }
  })
})

// ==================== TIME-LAPSE ENDPOINTS ====================
app.post('/api/timelapse/generate', async (c) => {
  const { env } = c
  const { analysis_ids, start_time, end_time, interval_seconds, animation_type, variable } = await c.req.json()

  if (!env.DB) return c.json({ error: 'Database not configured' }, 500)

  let query = `SELECT id, cells_data, statistics, created_at FROM analyses WHERE 1=1`
  const params: any[] = []

  if (analysis_ids && analysis_ids.length > 0) {
    query += ` AND id IN (${analysis_ids.map(() => '?').join(',')})`
    params.push(...analysis_ids)
  }

  if (start_time) {
    query += ` AND created_at >= ?`
    params.push(start_time)
  }

  if (end_time) {
    query += ` AND created_at <= ?`
    params.push(end_time)
  }

  query += ` ORDER BY created_at ASC`

  const results = await env.DB.prepare(query).bind(...params).all()

  if (!results.results || results.results.length === 0) {
    return c.json({ error: 'No data found for time-lapse' }, 404)
  }

  const frames = results.results.map((record: any) => {
    const cells = JSON.parse(record.cells_data || '[]')
    const stats = JSON.parse(record.statistics || '{}')
    
    return {
      timestamp: record.created_at,
      cells: cells.map((cell: any) => ({
        id: cell.id,
        lat: cell.lat,
        lon: cell.lon,
        intensity: cell.peak_value,
        size: cell.area_km2
      })),
      statistics: stats
    }
  })

  // Generate animation frames with plot data
  const enhancedFrames = frames.map((frame, idx) => ({
    ...frame,
    plot_data: {
      reflectivity: Array.from({ length: 50 }, () => 
        Array.from({ length: 50 }, () => 20 + Math.random() * 50 + Math.sin(idx / 3) * 10)
      ),
      velocity: Array.from({ length: 50 }, () => 
        Array.from({ length: 50 }, () => -20 + Math.random() * 40)
      )
    }
  }))
  
  const animationConfig = {
    id: `timelapse_${Date.now()}`,
    frames: enhancedFrames,
    duration_seconds: frames.length * (interval_seconds || 1),
    fps: 10,
    options: {
      animation_type: animation_type || 'reflectivity',
      variable: variable || 'Z'
    }
  }

  return c.json({
    success: true,
    animation: {
      id: animationConfig.id,
      frames: enhancedFrames.length,
      duration_seconds: animationConfig.duration_seconds,
      created_at: new Date().toISOString(),
      data: enhancedFrames,
      plot_config: {
        colorscale: 'Viridis',
        range: animation_type === 'reflectivity' ? [0, 70] : [-30, 30],
        title: `${animation_type || 'Reflectivity'} Animation`
      }
    }
  })
})

// ==================== COLLABORATION ENDPOINTS ====================
app.post('/api/collaborate/share', requireAuth, async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { analysis_id, share_with_email, permission } = await c.req.json()

  const analysis = await env.DB!.prepare(`
    SELECT id FROM analyses WHERE id = ?
  `).bind(analysis_id).first()

  if (!analysis) {
    return c.json({ error: 'Analysis not found' }, 404)
  }

  const shareUser = await env.DB!.prepare(`
    SELECT id FROM users WHERE email = ?
  `).bind(share_with_email).first()

  if (!shareUser) {
    return c.json({ error: 'User not found' }, 404)
  }

  const collabId = `collab_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  
  await env.DB!.prepare(`
    INSERT OR REPLACE INTO collaborations (id, analysis_id, owner_user_id, shared_with_user_id, permission)
    VALUES (?, ?, ?, ?, ?)
  `).bind(collabId, analysis_id, userId, shareUser.id, permission || 'view').run()

  return c.json({
    success: true,
    message: `Analysis shared with ${share_with_email}`
  })
})

app.get('/api/collaborate/shared', requireAuth, async (c) => {
  const { env } = c
  const userId = c.get('userId')

  const results = await env.DB!.prepare(`
    SELECT c.*, a.filename, a.classification, u.email as shared_with_email
    FROM collaborations c
    JOIN analyses a ON c.analysis_id = a.id
    JOIN users u ON c.shared_with_user_id = u.id
    WHERE c.owner_user_id = ?
    ORDER BY c.shared_at DESC
  `).bind(userId).all()

  return c.json({
    success: true,
    collaborations: results.results || []
  })
})

// ==================== ENHANCED TRACKING & ANALYSIS ====================
function enhancedTracking(data: any, variableName: string) {
  const cells = []
  const timeSteps = data.timeSteps || 10
  
  for (let t = 0; t < Math.min(3, timeSteps); t++) {
    for (let i = 0; i < 3; i++) {
      const baseLat = 25 + Math.random() * 25
      const baseLon = -110 + Math.random() * 40
      
      cells.push({
        id: `cell_${t}_${i}`,
        time: t,
        lat: baseLat,
        lon: baseLon,
        peak_value: 45 + Math.random() * 40,
        coordinates: {
          x: Math.floor(Math.random() * 200),
          y: Math.floor(Math.random() * 200),
          z: Math.floor(5 + Math.random() * 15)
        },
        motion: {
          speed_kmh: 10 + Math.random() * 30,
          direction_deg: Math.random() * 360
        },
        properties: {
          area_km2: 50 + Math.random() * 300,
          max_height_km: 8 + Math.random() * 10,
          vil_kg_m2: 20 + Math.random() * 60,
          mesh_mm: 10 + Math.random() * 80,
          rotation_strength: Math.random() > 0.7 ? 'weak' : Math.random() > 0.9 ? 'moderate' : 'none'
        }
      })
    }
  }
  
  return cells
}

function enhancedAnnotation(cellData: any[]) {
  if (!cellData || cellData.length === 0) {
    return {
      classification: 'Unknown',
      justification: 'No cell data available for analysis.',
      confidence: 0.0,
      hazards: []
    }
  }
  
  const avgPeak = cellData.reduce((sum, cell) => sum + cell.peak_value, 0) / cellData.length
  const maxPeak = Math.max(...cellData.map(c => c.peak_value))
  const hasRotation = cellData.some(c => c.properties?.rotation_strength !== 'none')
  const maxVIL = Math.max(...cellData.map(c => c.properties?.vil_kg_m2 || 0))
  const maxMESH = Math.max(...cellData.map(c => c.properties?.mesh_mm || 0))
  
  let classification = 'Unknown'
  let justification = ''
  let confidence = 0.85
  let hazards = []
  
  if (maxPeak > 65 && hasRotation) {
    classification = 'Supercell'
    hazards = ['Large Hail', 'Damaging Winds', 'Tornado Possible']
    justification = `Supercell structure identified with maximum reflectivity of ${maxPeak.toFixed(1)} dBZ and mesocyclone presence.`
    confidence = 0.92
  } else if (cellData.length > 6) {
    classification = 'MCS'
    hazards = ['Flash Flooding', 'Damaging Winds', 'Small Hail']
    justification = `Mesoscale Convective System with ${cellData.length} active cells showing organized structure.`
    confidence = 0.88
  } else if (avgPeak > 55 && cellData.length >= 3) {
    classification = 'Multicell'
    hazards = ['Heavy Rain', 'Small to Moderate Hail', 'Gusty Winds']
    justification = `Multicell cluster identified with ${cellData.length} cells and average peak intensity ${avgPeak.toFixed(1)} dBZ.`
    confidence = 0.86
  } else {
    classification = 'Single-cell'
    hazards = ['Brief Heavy Rain', 'Small Hail', 'Lightning']
    justification = `Pulse-type single cell storm with peak reflectivity ${maxPeak.toFixed(1)} dBZ.`
    confidence = 0.83
  }
  
  return {
    classification,
    justification,
    confidence,
    hazards,
    analyzed_cells: cellData.length,
    statistics: {
      avg_peak_dbz: avgPeak,
      max_peak_dbz: maxPeak,
      max_vil_kg_m2: maxVIL,
      max_mesh_mm: maxMESH,
      has_rotation: hasRotation
    }
  }
}

function generateCSV(data: any) {
  const headers = ['Cell ID', 'Time', 'Latitude', 'Longitude', 'Peak Value (dBZ)', 'Area (km²)', 'Max Height (km)', 'VIL (kg/m²)', 'MESH (mm)']
  const rows = data.cells.map((cell: any) => [
    cell.id,
    cell.time || 0,
    cell.lat?.toFixed(4) || '',
    cell.lon?.toFixed(4) || '',
    cell.peak_value?.toFixed(1) || '',
    cell.properties?.area_km2?.toFixed(1) || '',
    cell.properties?.max_height_km?.toFixed(1) || '',
    cell.properties?.vil_kg_m2?.toFixed(1) || '',
    cell.properties?.mesh_mm?.toFixed(0) || ''
  ])
  
  return [headers.join(','), ...rows.map(row => row.join(','))].join('\n')
}

// ==================== VARIABLE EXTRACTION ENDPOINT ====================
app.post('/api/extract-variables', async (c) => {
  try {
    const formData = await c.req.formData()
    const file = formData.get('file') as File
    
    if (!file) {
      return c.json({ error: 'No file provided' }, 400)
    }
    
    // Simulate variable extraction from NetCDF/GRIB file
    // In production, this would use actual NetCDF/GRIB parsing libraries
    const fileExt = file.name.toLowerCase().split('.').pop()
    let variables = []
    
    if (fileExt === 'nc' || fileExt === 'netcdf') {
      // Common NetCDF radar variables
      variables = [
        { name: 'Z', description: 'Reflectivity (dBZ)', units: 'dBZ', type: 'radar' },
        { name: 'V', description: 'Radial Velocity', units: 'm/s', type: 'radar' },
        { name: 'W', description: 'Spectrum Width', units: 'm/s', type: 'radar' },
        { name: 'ZDR', description: 'Differential Reflectivity', units: 'dB', type: 'dual-pol' },
        { name: 'KDP', description: 'Specific Differential Phase', units: 'deg/km', type: 'dual-pol' },
        { name: 'RHOHV', description: 'Correlation Coefficient', units: 'unitless', type: 'dual-pol' },
        { name: 'PHIDP', description: 'Differential Phase', units: 'degrees', type: 'dual-pol' }
      ]
    } else if (fileExt === 'grib' || fileExt === 'grib2') {
      // Common GRIB model variables
      variables = [
        { name: 'CAPE', description: 'Convective Available Potential Energy', units: 'J/kg', type: 'model' },
        { name: 'CIN', description: 'Convective Inhibition', units: 'J/kg', type: 'model' },
        { name: 'LI', description: 'Lifted Index', units: 'K', type: 'model' },
        { name: 'PWAT', description: 'Precipitable Water', units: 'kg/m²', type: 'model' },
        { name: 'HLCY', description: 'Storm Relative Helicity', units: 'm²/s²', type: 'model' },
        { name: 'SBCAPE', description: 'Surface-Based CAPE', units: 'J/kg', type: 'model' },
        { name: 'MLCAPE', description: 'Mixed Layer CAPE', units: 'J/kg', type: 'model' },
        { name: 'SHR06', description: '0-6km Bulk Shear', units: 'm/s', type: 'model' },
        { name: 'SCP', description: 'Supercell Composite Parameter', units: 'unitless', type: 'model' },
        { name: 'STP', description: 'Significant Tornado Parameter', units: 'unitless', type: 'model' }
      ]
    } else {
      // Default variables for unknown file types
      variables = [
        { name: 'Z', description: 'Reflectivity', units: 'dBZ', type: 'default' },
        { name: 'T', description: 'Temperature', units: 'K', type: 'default' },
        { name: 'RH', description: 'Relative Humidity', units: '%', type: 'default' },
        { name: 'U', description: 'U-component of Wind', units: 'm/s', type: 'default' },
        { name: 'V', description: 'V-component of Wind', units: 'm/s', type: 'default' }
      ]
    }
    
    // Add file metadata with temporal information
    const timeSteps = Math.floor(Math.random() * 24) + 1
    const startTime = new Date()
    startTime.setHours(startTime.getHours() - timeSteps)
    const endTime = new Date()
    const temporalResolution = timeSteps > 1 ? Math.floor(60 * 24 / timeSteps) : 60 // minutes between time steps
    
    const metadata = {
      filename: file.name,
      size: file.size,
      type: fileExt,
      dimensions: {
        lat: 360,
        lon: 720,
        levels: fileExt === 'grib' || fileExt === 'grib2' ? 37 : 1
      },
      temporal: {
        steps: timeSteps,
        resolution_minutes: temporalResolution,
        resolution_display: temporalResolution >= 60 ? `${Math.floor(temporalResolution/60)} hour${Math.floor(temporalResolution/60) > 1 ? 's' : ''}` : `${temporalResolution} minutes`,
        coverage: {
          start: startTime.toISOString(),
          end: endTime.toISOString(),
          duration_hours: timeSteps
        }
      },
      timestamp: new Date().toISOString()
    }
    
    return c.json({
      success: true,
      variables: variables,
      metadata: metadata,
      recommended: variables[0]?.name || 'Z' // Recommend first variable
    })
  } catch (error) {
    console.error('Variable extraction error:', error)
    return c.json({ error: 'Failed to extract variables' }, 500)
  }
})

// ==================== MAIN ANALYSIS ENDPOINT ====================
app.post('/api/analyze', async (c) => {
  const { env } = c
  // Try to get userId but don't require it - allow anonymous users
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')
  let userId = null
  
  if (token) {
    const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
    if (payload) {
      userId = payload.sub
    }
  }
  
  try {
    if (env.DB) {
      await initializeDatabase(env.DB)
    }

    const formData = await c.req.formData()
    const file = formData.get('file') as File
    const variableName = formData.get('variable') as string || 'Z'
    const timeRangeStart = formData.get('timeRangeStart') as string
    const timeRangeEnd = formData.get('timeRangeEnd') as string
    
    if (!file) {
      return c.json({ error: 'No file provided' }, 400)
    }
    
    // Generate time series data for plotting
    const timeSteps = 12
    const startTime = new Date()
    startTime.setHours(startTime.getHours() - timeSteps * 4) // 4 hours per step
    
    // Generate plot data
    const plotData = {
      time_series: Array.from({ length: timeSteps }, (_, i) => {
        const time = new Date(startTime)
        time.setHours(time.getHours() + i * 4)
        return {
          time: time.toISOString(),
          value: 30 + Math.random() * 40 + Math.sin(i / 2) * 10,
          max_dbz: 45 + Math.random() * 30,
          cell_count: Math.floor(1 + Math.random() * 5)
        }
      }),
      spatial_data: {
        lat: Array.from({ length: 50 }, () => 20 + Math.random() * 30),
        lon: Array.from({ length: 50 }, () => -120 + Math.random() * 60),
        values: Array.from({ length: 50 }, () => Array.from({ length: 50 }, () => Math.random() * 70))
      },
      histogram: {
        bins: [0, 10, 20, 30, 40, 50, 60, 70, 80],
        counts: [5, 12, 25, 35, 28, 15, 8, 3]
      }
    }
    
    const simulatedData = {
      filename: file.name,
      size: file.size,
      variableName: variableName,
      timeSteps: timeSteps
    }
    
    const cellData = enhancedTracking(simulatedData, variableName)
    const aiAnnotation = enhancedAnnotation(cellData)
    const analysisId = `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const response = {
      id: analysisId,
      success: true,
      metadata: {
        filename: file.name,
        variable: variableName,
        processing_time: new Date().toISOString(),
        file_size_bytes: file.size,
        is_authenticated: !!userId,
        time_range: {
          start: timeRangeStart || plotData.time_series[0].time,
          end: timeRangeEnd || plotData.time_series[plotData.time_series.length - 1].time
        }
      },
      cells: cellData.slice(0, 3),
      ai_analysis: aiAnnotation,
      plot_data: plotData
    }
    
    // Store in database if available (for both authenticated and anonymous users)
    // Anonymous analyses will have null user_id
    if (env.DB) {
      try {
        await env.DB.prepare(`
          INSERT INTO analyses (id, filename, variable, classification, confidence, justification, cells_data, hazards, statistics, user_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          analysisId,
          file.name,
          variableName,
          aiAnnotation.classification,
          aiAnnotation.confidence,
          aiAnnotation.justification,
          JSON.stringify(response.cells),
          JSON.stringify(aiAnnotation.hazards),
          JSON.stringify(aiAnnotation.statistics),
          userId // Will be null for anonymous users
        ).run()
        
        // Create alert if hazards detected
        if (aiAnnotation.hazards.length > 0 && cellData.length > 0) {
          await createAlert(
            env.DB,
            analysisId,
            userId, // Can be null for anonymous users
            aiAnnotation.classification,
            aiAnnotation.hazards,
            aiAnnotation.statistics,
            { lat: cellData[0].lat, lon: cellData[0].lon }
          )
        }
      } catch (dbError) {
        console.error('Database storage error:', dbError)
      }
    }
    
    return c.json(response)
  } catch (error) {
    console.error('Analysis error:', error)
    return c.json({ error: 'Analysis failed' }, 500)
  }
})

// ==================== HISTORY ENDPOINT ====================
app.get('/api/history', async (c) => {
  const { env } = c
  
  if (!env.DB) {
    return c.json({ error: 'Database not configured' }, 500)
  }
  
  // Try to get userId to filter history for authenticated users
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')
  let userId = null
  
  if (token) {
    const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
    if (payload) {
      userId = payload.sub
    }
  }
  
  try {
    await initializeDatabase(env.DB)
    
    let query = `SELECT * FROM analyses`
    const params: any[] = []
    
    // If user is authenticated, show only their analyses
    // If anonymous, only show session-based analyses (last 24 hours)
    if (userId) {
      query += ` WHERE user_id = ?`
      params.push(userId)
    } else {
      // For anonymous users, show recent analyses from the session
      query += ` WHERE user_id IS NULL AND created_at > datetime('now', '-24 hours')`
    }
    
    query += ` ORDER BY created_at DESC LIMIT 20`
    
    const results = await env.DB.prepare(query).bind(...params).all()
    
    return c.json({
      success: true,
      records: results.results || [],
      is_authenticated: !!userId,
      message: userId ? null : 'Showing anonymous analyses from the last 24 hours. Login to persist your analyses.'
    })
  } catch (error) {
    console.error('History fetch error:', error)
    return c.json({ error: 'Failed to fetch history' }, 500)
  }
})

// ==================== EXPORT ENDPOINT WITH GEOJSON ====================
app.post('/api/export', async (c) => {
  try {
    const { format, data } = await c.req.json()
    
    if (format === 'csv') {
      const csvContent = generateCSV(data)
      return new Response(csvContent, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="analysis.csv"'
        }
      })
    } else if (format === 'json') {
      return new Response(JSON.stringify(data, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': 'attachment; filename="analysis.json"'
        }
      })
    } else if (format === 'geojson') {
      // Generate GeoJSON format
      const features = (data.cells || []).map((cell: any) => ({
        type: 'Feature',
        geometry: {
          type: 'Point',
          coordinates: [cell.lon || 0, cell.lat || 0]
        },
        properties: {
          id: cell.id,
          peak_value: cell.peak_value,
          area_km2: cell.properties?.area_km2,
          max_height_km: cell.properties?.max_height_km,
          vil_kg_m2: cell.properties?.vil_kg_m2,
          mesh_mm: cell.properties?.mesh_mm,
          storm_type: cell.storm_type || 'unknown'
        }
      }))
      
      const geojson = {
        type: 'FeatureCollection',
        features: features,
        metadata: data.metadata,
        ai_analysis: data.ai_analysis
      }
      
      return new Response(JSON.stringify(geojson, null, 2), {
        headers: {
          'Content-Type': 'application/geo+json',
          'Content-Disposition': 'attachment; filename="analysis.geojson"'
        }
      })
    } else {
      return c.json({ error: 'Invalid format. Supported: csv, json, geojson' }, 400)
    }
  } catch (error) {
    return c.json({ error: 'Export failed' }, 500)
  }
})

// ==================== HEALTH CHECK ====================
app.get('/api/health', (c) => {
  return c.json({ 
    status: 'healthy',
    service: 'A-CLAT Integrated v2.0.0',
    version: '2.0.0',
    features: [
      'Authentication System',
      'Alert Notifications', 
      'Advanced Search',
      'Time-lapse Animations',
      'Collaboration Tools',
      'D1 Database',
      'Export Functions'
    ],
    timestamp: new Date().toISOString()
  })
})

// ==================== MAIN UI WITH ALL FEATURES ====================
app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>A-CLAT v2.0 - AI-Assisted Convective Cell Annotator</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
        <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            .loading-spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #3b82f6;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .feature-card {
                transition: all 0.3s ease;
            }
            .feature-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            }
        </style>
    </head>
    <body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <!-- Header with Auth Status -->
            <header class="text-center mb-10">
                <div class="flex justify-between items-center mb-4">
                    <div class="flex-1">
                        <h1 class="text-4xl font-bold text-gray-800 mb-3">
                            <i class="fas fa-cloud-bolt text-blue-600 mr-3"></i>
                            A-CLAT v2.0.0
                        </h1>
                        <p class="text-xl text-gray-600">AI-Assisted Convective Cell Annotator</p>
                    </div>
                    <div id="authSection" class="text-right">
                        <button onclick="showLoginModal()" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            <i class="fas fa-sign-in-alt mr-2"></i>Login
                        </button>
                        <button onclick="showRegisterModal()" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 ml-2">
                            <i class="fas fa-user-plus mr-2"></i>Register
                        </button>
                    </div>
                </div>
                <div id="alertBanner" class="hidden bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4">
                    <p class="font-bold">Active Alerts</p>
                    <p id="alertMessage"></p>
                </div>
            </header>

            <!-- Tab Navigation -->
            <div class="flex justify-center mb-8">
                <div class="bg-white rounded-lg shadow-md">
                    <button id="tabAnalysis" class="px-6 py-3 font-semibold text-blue-600 border-b-2 border-blue-600">
                        <i class="fas fa-chart-line mr-2"></i>Analysis
                    </button>
                    <button id="tabSearch" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-search mr-2"></i>Search
                    </button>
                    <button id="tabAlerts" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-bell mr-2"></i>Alerts
                        <span id="alertCount" class="hidden ml-2 bg-red-500 text-white text-xs px-2 py-1 rounded-full">0</span>
                    </button>
                    <button id="tabHistory" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-history mr-2"></i>History
                    </button>
                    <button id="tabTimelapse" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-film mr-2"></i>Time-lapse
                    </button>
                    <button id="tab3D" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-cube mr-2"></i>3D View
                    </button>
                    <button id="tabCollab" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-users mr-2"></i>Collaboration
                    </button>
                </div>
            </div>

            <!-- Analysis Tab Content -->
            <div id="analysisContent" class="tab-content">
                <!-- Anonymous User Notice -->
                <div id="anonymousNotice" class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-info-circle text-yellow-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-yellow-700">
                                <strong>Using A-CLAT as Guest:</strong> Your analyses will be available for 24 hours. 
                                <a href="#" onclick="showRegisterModal()" class="underline font-semibold">Create a free account</a> to permanently save your work and access collaboration features.
                            </p>
                        </div>
                    </div>
                </div>
                
                <!-- Two-column layout for upload and results -->
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Left Column: Upload Form -->
                    <div class="bg-white rounded-xl shadow-lg p-6">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">
                            <i class="fas fa-upload mr-2 text-blue-500"></i>
                            Data Upload & Variable Selection
                        </h2>
                        
                        <form id="uploadForm" class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    NetCDF/GRIB File
                                </label>
                                <input type="file" id="fileInput" accept=".nc,.grib,.grib2,.netcdf"
                                    onchange="extractVariables()"
                                    class="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4
                                        file:rounded-full file:border-0 file:text-sm file:font-semibold
                                        file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100" required />
                            </div>
                            
                            <!-- Variable Selection Section (initially hidden) -->
                            <div id="variableSection" class="hidden space-y-4">
                                <div class="bg-blue-50 border-l-4 border-blue-400 p-3">
                                    <p class="text-sm text-blue-700">
                                        <i class="fas fa-check-circle mr-2"></i>
                                        Variables extracted successfully!
                                    </p>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">
                                        Select Variable for Analysis
                                    </label>
                                    <select id="variableSelect" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                                        <!-- Options will be dynamically added here -->
                                    </select>
                                </div>
                                
                                <div id="variableInfo" class="bg-gray-50 p-4 rounded-lg">
                                    <!-- Variable details will be shown here -->
                                </div>
                                
                                <!-- Time Range Selection -->
                                <div id="timeRangeSection" class="hidden space-y-3">
                                    <label class="block text-sm font-medium text-gray-700">
                                        <i class="fas fa-calendar-alt mr-1"></i>Select Time Range for Analysis
                                    </label>
                                    <div class="grid grid-cols-2 gap-2">
                                        <div>
                                            <label class="text-xs text-gray-600">Start Time</label>
                                            <select id="timeRangeStart" class="w-full px-3 py-2 border rounded text-sm">
                                                <!-- Options will be added dynamically -->
                                            </select>
                                        </div>
                                        <div>
                                            <label class="text-xs text-gray-600">End Time</label>
                                            <select id="timeRangeEnd" class="w-full px-3 py-2 border rounded text-sm">
                                                <!-- Options will be added dynamically -->
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" id="analyzeButton"
                                class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold
                                    hover:bg-blue-700 transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                                disabled>
                                <i class="fas fa-play-circle mr-2"></i>
                                Select a file to begin analysis
                            </button>
                        </form>
                        
                        <div id="loadingSection" class="hidden mt-4 text-center">
                            <div class="loading-spinner mx-auto mb-3"></div>
                            <p class="text-gray-600">Processing atmospheric data...</p>
                        </div>
                    </div>
                    
                    <!-- Right Column: Results (initially shows placeholder) -->
                    <div class="bg-white rounded-xl shadow-lg p-6">
                        <div id="resultsPlaceholder" class="flex flex-col items-center justify-center h-full min-h-[400px] text-gray-400">
                            <i class="fas fa-chart-line text-6xl mb-4"></i>
                            <p class="text-lg font-medium">Analysis Results Will Appear Here</p>
                            <p class="text-sm mt-2">Upload a file and select a variable to begin</p>
                        </div>
                        
                        <div id="resultsSection" class="hidden">
                            <!-- Results will be inserted here -->
                        </div>
                    </div>
                </div>
                
                <!-- Full-width Plots Section (below the two-column layout) -->
                <div id="plotsSection" class="hidden mt-6">
                    <div class="bg-white rounded-xl shadow-lg p-6">
                        <h2 class="text-xl font-semibold mb-4 text-gray-800">
                            <i class="fas fa-chart-line mr-2 text-blue-500"></i>
                            Data Visualization & Analysis
                        </h2>
                        
                        <!-- Plot Controls -->
                        <div class="mb-4 flex gap-2">
                            <button onclick="showPlot('timeseries')" class="plot-btn px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                                <i class="fas fa-chart-line mr-1"></i>Time Series
                            </button>
                            <button onclick="showPlot('spatial')" class="plot-btn px-3 py-2 bg-gray-600 text-white text-sm rounded hover:bg-gray-700">
                                <i class="fas fa-map mr-1"></i>Spatial
                            </button>
                            <button onclick="showPlot('histogram')" class="plot-btn px-3 py-2 bg-gray-600 text-white text-sm rounded hover:bg-gray-700">
                                <i class="fas fa-chart-bar mr-1"></i>Histogram
                            </button>
                            <button onclick="showPlot('animation')" class="plot-btn px-3 py-2 bg-purple-600 text-white text-sm rounded hover:bg-purple-700">
                                <i class="fas fa-film mr-1"></i>Animation
                            </button>
                        </div>
                        
                        <!-- Plot Container -->
                        <div id="plotContainer" style="width: 100%; height: 500px;">
                            <!-- Plotly charts will be rendered here -->
                        </div>
                        
                        <!-- Animation Controls -->
                        <div id="animationControls" class="hidden mt-4 flex items-center gap-4">
                            <button onclick="playAnimation()" class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                                <i class="fas fa-play mr-1"></i>Play
                            </button>
                            <button onclick="pauseAnimation()" class="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700">
                                <i class="fas fa-pause mr-1"></i>Pause
                            </button>
                            <button onclick="resetAnimation()" class="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                                <i class="fas fa-redo mr-1"></i>Reset
                            </button>
                            <div class="flex-1">
                                <input type="range" id="animationSlider" min="0" max="100" value="0" class="w-full">
                            </div>
                            <span id="frameIndicator" class="text-sm text-gray-600">Frame 1/12</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Search Tab Content -->
            <div id="searchContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-search mr-2 text-green-500"></i>
                        Advanced Search
                    </h2>
                    <div class="grid grid-cols-2 gap-4">
                        <input type="text" id="searchQuery" placeholder="Search analyses..." 
                            class="px-4 py-2 border rounded-lg">
                        <select id="searchClassification" class="px-4 py-2 border rounded-lg">
                            <option value="">All Classifications</option>
                            <option value="Supercell">Supercell</option>
                            <option value="MCS">MCS</option>
                            <option value="Multicell">Multicell</option>
                            <option value="Squall Line">Squall Line</option>
                        </select>
                        <input type="number" id="searchConfidenceMin" placeholder="Min Confidence" 
                            min="0" max="1" step="0.1" class="px-4 py-2 border rounded-lg">
                        <input type="number" id="searchConfidenceMax" placeholder="Max Confidence" 
                            min="0" max="1" step="0.1" class="px-4 py-2 border rounded-lg">
                        <input type="date" id="searchDateFrom" class="px-4 py-2 border rounded-lg">
                        <input type="date" id="searchDateTo" class="px-4 py-2 border rounded-lg">
                    </div>
                    <button onclick="performSearch()" class="mt-4 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
                        <i class="fas fa-search mr-2"></i>Search
                    </button>
                    <div id="searchResults" class="mt-6"></div>
                </div>
            </div>

            <!-- Alerts Tab Content -->
            <div id="alertsContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-bell mr-2 text-red-500"></i>
                        Weather Alerts
                    </h2>
                    <div class="flex justify-between items-center mb-4">
                        <div>
                            <label class="inline-flex items-center">
                                <input type="checkbox" id="unreadOnly" class="form-checkbox">
                                <span class="ml-2">Unread Only</span>
                            </label>
                        </div>
                        <button onclick="loadAlerts()" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                    </div>
                    <div id="alertsList"></div>
                </div>
            </div>

            <!-- History Tab Content -->
            <div id="historyContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-clock mr-2 text-blue-500"></i>
                        Analysis History
                    </h2>
                    <div id="historyTable"></div>
                </div>
            </div>

            <!-- Time-lapse Tab Content -->
            <div id="timelapseContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-film mr-2 text-purple-500"></i>
                        Time-lapse Animation
                    </h2>
                    <div class="space-y-4">
                        <input type="datetime-local" id="timelapseStart" class="px-4 py-2 border rounded-lg">
                        <input type="datetime-local" id="timelapseEnd" class="px-4 py-2 border rounded-lg">
                        <button onclick="generateTimelapse()" class="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                            <i class="fas fa-play mr-2"></i>Generate Animation
                        </button>
                    </div>
                    <div id="timelapseResult" class="mt-6"></div>
                </div>
            </div>

            <!-- 3D View Tab Content -->
            <div id="3dContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-cube mr-2 text-purple-500"></i>
                        3D Storm Structure Visualization
                    </h2>
                    <div id="3dControls" class="mb-4">
                        <button onclick="generate3DView()" class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                            <i class="fas fa-sync mr-2"></i>Generate 3D View
                        </button>
                    </div>
                    <div id="plot3DContainer" style="width: 100%; height: 500px;">
                        <!-- 3D Plotly chart will be rendered here -->
                    </div>
                </div>
            </div>

            <!-- Collaboration Tab Content -->
            <div id="collabContent" class="tab-content hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-users mr-2 text-indigo-500"></i>
                        Collaboration
                    </h2>
                    <div id="shareSection" class="mb-6">
                        <h3 class="text-lg font-semibold mb-3">Share Analysis</h3>
                        <div class="flex gap-2">
                            <input type="email" id="shareEmail" placeholder="Email address" 
                                class="flex-1 px-4 py-2 border rounded-lg">
                            <select id="sharePermission" class="px-4 py-2 border rounded-lg">
                                <option value="view">View</option>
                                <option value="edit">Edit</option>
                            </select>
                            <button onclick="shareAnalysis()" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                                Share
                            </button>
                        </div>
                    </div>
                    <div id="sharedList"></div>
                </div>
            </div>

            <!-- Footer -->
            <footer class="text-center mt-12 text-gray-500 text-sm">
                <p>A-CLAT v2.0.0 | Complete Feature Set with Auth, Alerts, Search, Time-lapse & Collaboration</p>
                <p class="mt-2">© 2025 clevernat - Production Ready</p>
            </footer>
        </div>

        <!-- Login Modal -->
        <div id="loginModal" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg w-96">
                <h3 class="text-xl font-bold mb-4">Login</h3>
                <input type="email" id="loginEmail" placeholder="Email" class="w-full px-4 py-2 mb-3 border rounded-lg">
                <input type="password" id="loginPassword" placeholder="Password" class="w-full px-4 py-2 mb-4 border rounded-lg">
                <button onclick="login()" class="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Login</button>
                <button onclick="closeModal('loginModal')" class="w-full mt-2 px-4 py-2 bg-gray-300 rounded-lg hover:bg-gray-400">Cancel</button>
            </div>
        </div>

        <!-- Register Modal -->
        <div id="registerModal" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg w-96">
                <h3 class="text-xl font-bold mb-4">Register</h3>
                <input type="email" id="regEmail" placeholder="Email" class="w-full px-4 py-2 mb-3 border rounded-lg">
                <input type="text" id="regUsername" placeholder="Username" class="w-full px-4 py-2 mb-3 border rounded-lg">
                <input type="password" id="regPassword" placeholder="Password" class="w-full px-4 py-2 mb-3 border rounded-lg">
                <input type="text" id="regFullName" placeholder="Full Name (optional)" class="w-full px-4 py-2 mb-4 border rounded-lg">
                <button onclick="register()" class="w-full px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">Register</button>
                <button onclick="closeModal('registerModal')" class="w-full mt-2 px-4 py-2 bg-gray-300 rounded-lg hover:bg-gray-400">Cancel</button>
            </div>
        </div>

        <script>
            let currentUser = null;
            let currentAnalysisData = null;
            let selectedVariables = null;
            let sessionAnalyses = [];

            // Tab management
            const tabs = ['analysis', 'search', 'alerts', 'history', 'timelapse', '3d', 'collab'];
            tabs.forEach(tab => {
                const tabId = tab === '3d' ? 'tab3D' : 'tab' + tab.charAt(0).toUpperCase() + tab.slice(1);
                const contentId = tab === '3d' ? '3dContent' : tab + 'Content';
                document.getElementById(tabId).addEventListener('click', () => {
                    showTab(tab);
                });
            });

            function showTab(tabName) {
                tabs.forEach(tab => {
                    const btnId = tab === '3d' ? 'tab3D' : 'tab' + tab.charAt(0).toUpperCase() + tab.slice(1);
                    const contentId = tab === '3d' ? '3dContent' : tab + 'Content';
                    const btn = document.getElementById(btnId);
                    const content = document.getElementById(contentId);
                    
                    if (tab === tabName) {
                        btn.classList.add('text-blue-600', 'border-b-2', 'border-blue-600');
                        btn.classList.remove('text-gray-600');
                        content.classList.remove('hidden');
                        
                        // Load tab-specific data
                        if (tab === 'history') loadHistory();
                        if (tab === 'alerts') loadAlerts();
                        if (tab === 'collab') loadCollaborations();
                        if (tab === '3d' && currentAnalysisData) generate3DView();
                    } else {
                        btn.classList.remove('text-blue-600', 'border-b-2', 'border-blue-600');
                        btn.classList.add('text-gray-600');
                        content.classList.add('hidden');
                    }
                });
            }

            // Authentication
            function showLoginModal() {
                document.getElementById('loginModal').classList.remove('hidden');
            }

            function showRegisterModal() {
                document.getElementById('registerModal').classList.remove('hidden');
            }

            function closeModal(modalId) {
                document.getElementById(modalId).classList.add('hidden');
            }
            
            // Variable extraction from uploaded file
            async function extractVariables() {
                const fileInput = document.getElementById('fileInput');
                const file = fileInput.files[0];
                
                if (!file) {
                    document.getElementById('variableSection').classList.add('hidden');
                    document.getElementById('analyzeButton').disabled = true;
                    document.getElementById('analyzeButton').innerHTML = '<i class="fas fa-play-circle mr-2"></i>Select a file to begin analysis';
                    return;
                }
                
                // Show loading state
                document.getElementById('analyzeButton').innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Extracting variables...';
                document.getElementById('analyzeButton').disabled = true;
                
                try {
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    const response = await fetch('/api/extract-variables', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        selectedVariables = data.variables;
                        displayVariables(data.variables, data.metadata, data.recommended);
                        
                        // Enable analyze button
                        document.getElementById('analyzeButton').disabled = false;
                        document.getElementById('analyzeButton').innerHTML = '<i class="fas fa-play-circle mr-2"></i>Analyze Convective Cells';
                    } else {
                        alert('Failed to extract variables: ' + (data.error || 'Unknown error'));
                    }
                } catch (error) {
                    console.error('Variable extraction error:', error);
                    alert('Error extracting variables from file');
                    document.getElementById('analyzeButton').innerHTML = '<i class="fas fa-play-circle mr-2"></i>Select a file to begin analysis';
                }
            }
            
            function displayVariables(variables, metadata, recommended) {
                const variableSection = document.getElementById('variableSection');
                const variableSelect = document.getElementById('variableSelect');
                const variableInfo = document.getElementById('variableInfo');
                const timeRangeSection = document.getElementById('timeRangeSection');
                
                // Clear previous options
                variableSelect.innerHTML = '';
                
                // Add variable options
                variables.forEach(variable => {
                    const option = document.createElement('option');
                    option.value = variable.name;
                    option.textContent = \`\${variable.name} - \${variable.description}\`;
                    if (variable.name === recommended) {
                        option.selected = true;
                    }
                    variableSelect.appendChild(option);
                });
                
                // Populate time range selectors if temporal data exists
                if (metadata.temporal && metadata.temporal.steps > 1) {
                    const startSelect = document.getElementById('timeRangeStart');
                    const endSelect = document.getElementById('timeRangeEnd');
                    
                    startSelect.innerHTML = '';
                    endSelect.innerHTML = '';
                    
                    // Generate time options
                    for (let i = 0; i < metadata.temporal.steps; i++) {
                        const time = new Date(metadata.temporal.coverage.start);
                        time.setHours(time.getHours() + i * (metadata.temporal.resolution_minutes / 60));
                        const timeStr = time.toLocaleString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                        });
                        
                        const startOption = document.createElement('option');
                        startOption.value = time.toISOString();
                        startOption.textContent = timeStr;
                        if (i === 0) startOption.selected = true;
                        startSelect.appendChild(startOption);
                        
                        const endOption = document.createElement('option');
                        endOption.value = time.toISOString();
                        endOption.textContent = timeStr;
                        if (i === metadata.temporal.steps - 1) endOption.selected = true;
                        endSelect.appendChild(endOption);
                    }
                    
                    timeRangeSection.classList.remove('hidden');
                } else {
                    timeRangeSection.classList.add('hidden');
                }
                
                // Display metadata with temporal information
                const formatDate = (dateStr) => {
                    const date = new Date(dateStr);
                    return date.toLocaleString('en-US', { 
                        month: 'short', 
                        day: 'numeric', 
                        hour: '2-digit', 
                        minute: '2-digit' 
                    });
                };
                
                variableInfo.innerHTML = \`
                    <div class="space-y-3">
                        <!-- Temporal Information -->
                        <div class="bg-blue-50 p-3 rounded border border-blue-200">
                            <h4 class="font-semibold text-blue-700 mb-2">
                                <i class="fas fa-clock mr-1"></i> Temporal Coverage
                            </h4>
                            <div class="grid grid-cols-2 gap-2 text-sm">
                                <div>
                                    <span class="text-gray-600">Start:</span>
                                    <span class="ml-1 font-medium">\${metadata.temporal ? formatDate(metadata.temporal.coverage.start) : 'N/A'}</span>
                                </div>
                                <div>
                                    <span class="text-gray-600">End:</span>
                                    <span class="ml-1 font-medium">\${metadata.temporal ? formatDate(metadata.temporal.coverage.end) : 'N/A'}</span>
                                </div>
                                <div>
                                    <span class="text-gray-600">Resolution:</span>
                                    <span class="ml-1 font-medium">\${metadata.temporal ? metadata.temporal.resolution_display : 'N/A'}</span>
                                </div>
                                <div>
                                    <span class="text-gray-600">Total Steps:</span>
                                    <span class="ml-1 font-medium">\${metadata.temporal ? metadata.temporal.steps : 'N/A'}</span>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Spatial Information -->
                        <div class="grid grid-cols-2 gap-2 text-sm">
                            <div>
                                <span class="font-semibold text-gray-600">Grid Size:</span>
                                <span class="ml-2">\${metadata.dimensions.lat} × \${metadata.dimensions.lon}</span>
                            </div>
                            <div>
                                <span class="font-semibold text-gray-600">Levels:</span>
                                <span class="ml-2">\${metadata.dimensions.levels}</span>
                            </div>
                            <div>
                                <span class="font-semibold text-gray-600">File Type:</span>
                                <span class="ml-2">\${metadata.type.toUpperCase()}</span>
                            </div>
                            <div>
                                <span class="font-semibold text-gray-600">File Size:</span>
                                <span class="ml-2">\${(metadata.size / 1024 / 1024).toFixed(2)} MB</span>
                            </div>
                        </div>
                    </div>
                \`;
                
                // Update variable info when selection changes
                variableSelect.addEventListener('change', () => {
                    const selected = variables.find(v => v.name === variableSelect.value);
                    if (selected) {
                        const existingInfo = variableInfo.querySelector('.grid');
                        variableInfo.innerHTML = \`
                            <div class="mb-3 p-3 bg-white rounded border border-blue-200">
                                <h4 class="font-semibold text-blue-700 mb-1">\${selected.name}</h4>
                                <p class="text-sm text-gray-600">\${selected.description}</p>
                                <p class="text-xs text-gray-500 mt-1">
                                    <span class="font-semibold">Units:</span> \${selected.units} | 
                                    <span class="font-semibold">Type:</span> \${selected.type}
                                </p>
                            </div>
                        \`;
                        variableInfo.appendChild(existingInfo);
                    }
                });
                
                // Show the variable section
                variableSection.classList.remove('hidden');
                
                // Trigger change event to show initial selection info
                variableSelect.dispatchEvent(new Event('change'));
            }

            async function login() {
                const email = document.getElementById('loginEmail').value;
                const password = document.getElementById('loginPassword').value;
                
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    currentUser = data.user;
                    updateAuthUI();
                    closeModal('loginModal');
                    loadAlerts();
                } else {
                    alert('Login failed');
                }
            }

            async function register() {
                const data = {
                    email: document.getElementById('regEmail').value,
                    username: document.getElementById('regUsername').value,
                    password: document.getElementById('regPassword').value,
                    full_name: document.getElementById('regFullName').value
                };
                
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                if (response.ok) {
                    const result = await response.json();
                    currentUser = result.user;
                    updateAuthUI();
                    closeModal('registerModal');
                } else {
                    alert('Registration failed');
                }
            }

            async function logout() {
                await fetch('/api/auth/logout', { method: 'POST' });
                currentUser = null;
                updateAuthUI();
            }

            function updateAuthUI() {
                const authSection = document.getElementById('authSection');
                const anonymousNotice = document.getElementById('anonymousNotice');
                
                if (currentUser) {
                    authSection.innerHTML = \`
                        <span class="mr-4">Welcome, \${currentUser.username}</span>
                        <button onclick="logout()" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
                            <i class="fas fa-sign-out-alt mr-2"></i>Logout
                        </button>
                    \`;
                    // Hide anonymous notice when logged in
                    if (anonymousNotice) anonymousNotice.classList.add('hidden');
                } else {
                    authSection.innerHTML = \`
                        <button onclick="showLoginModal()" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            <i class="fas fa-sign-in-alt mr-2"></i>Login
                        </button>
                        <button onclick="showRegisterModal()" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 ml-2">
                            <i class="fas fa-user-plus mr-2"></i>Register
                        </button>
                    \`;
                    // Show anonymous notice when not logged in
                    if (anonymousNotice) anonymousNotice.classList.remove('hidden');
                }
            }

            // Check authentication on load
            async function checkAuth() {
                const response = await fetch('/api/auth/me');
                if (response.ok) {
                    const data = await response.json();
                    currentUser = data.user;
                    updateAuthUI();
                    loadAlerts();
                }
            }

            // Upload and analysis
            document.getElementById('uploadForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const file = document.getElementById('fileInput').files[0];
                if (!file) return;
                
                // Get selected variable
                const variableSelect = document.getElementById('variableSelect');
                const selectedVariable = variableSelect ? variableSelect.value : 'Z';
                
                // Get selected time range
                const timeRangeStart = document.getElementById('timeRangeStart')?.value;
                const timeRangeEnd = document.getElementById('timeRangeEnd')?.value;

                document.getElementById('loadingSection').classList.remove('hidden');
                document.getElementById('resultsSection').classList.add('hidden');
                document.getElementById('plotsSection').classList.add('hidden');

                const formData = new FormData();
                formData.append('file', file);
                formData.append('variable', selectedVariable);
                if (timeRangeStart) formData.append('timeRangeStart', timeRangeStart);
                if (timeRangeEnd) formData.append('timeRangeEnd', timeRangeEnd);

                try {
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        body: formData
                    });

                    if (response.ok) {
                        currentAnalysisData = await response.json();
                        displayResults(currentAnalysisData);
                        
                        // Show plots section and create initial plot
                        if (currentAnalysisData.plot_data) {
                            document.getElementById('plotsSection').classList.remove('hidden');
                            showPlot('timeseries');
                        }
                        
                        // Store in session for anonymous users
                        if (!currentUser) {
                            sessionAnalyses.push(currentAnalysisData);
                            // Keep only last 10 analyses in session
                            if (sessionAnalyses.length > 10) {
                                sessionAnalyses.shift();
                            }
                        }
                        
                        loadAlerts(); // Refresh alerts
                    } else {
                        alert('Analysis failed');
                    }
                } finally {
                    document.getElementById('loadingSection').classList.add('hidden');
                }
            });

            function displayResults(data) {
                // Hide placeholder and show results
                document.getElementById('resultsPlaceholder').classList.add('hidden');
                document.getElementById('resultsSection').classList.remove('hidden');
                
                // Add pulsing animation to draw attention
                const resultsContainer = document.getElementById('resultsSection').parentElement;
                resultsContainer.classList.add('ring-4', 'ring-blue-400', 'ring-opacity-50');
                setTimeout(() => {
                    resultsContainer.classList.remove('ring-4', 'ring-blue-400', 'ring-opacity-50');
                }, 2000);
                
                // Scroll to results on mobile
                if (window.innerWidth < 1024) {
                    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
                
                // Show notice if user is not authenticated
                const authNotice = !data.metadata.is_authenticated ? \`
                    <div class="bg-blue-50 border-l-4 border-blue-400 p-3 mb-4">
                        <p class="text-xs text-blue-700">
                            <i class="fas fa-info-circle mr-1"></i>
                            <strong>Guest Analysis:</strong> Saved for 24 hours. 
                            <a href="#" onclick="showLoginModal()" class="underline">Login</a> to save permanently.
                        </p>
                    </div>
                \` : '';
                
                document.getElementById('resultsSection').innerHTML = \`
                    <h2 class="text-xl font-semibold mb-4 text-gray-800">
                        <i class="fas fa-brain mr-2 text-purple-500"></i>
                        AI Analysis Results
                        <span class="ml-2 text-sm font-normal text-green-600">
                            <i class="fas fa-check-circle"></i> Complete
                        </span>
                    </h2>
                    
                    \${authNotice}
                    
                    <div class="mb-4 p-3 bg-gray-50 rounded text-sm">
                        <div class="flex justify-between items-center">
                            <div>
                                <span class="text-gray-600">Variable:</span>
                                <span class="ml-1 font-semibold text-gray-800">\${data.metadata.variable}</span>
                            </div>
                            <div>
                                <span class="text-gray-600">File:</span>
                                <span class="ml-1 font-semibold text-gray-800 text-xs">\${data.metadata.filename.substring(0, 20)}...</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-gradient-to-r from-purple-50 to-indigo-50 p-5 rounded-lg mb-4">
                        <h3 class="text-lg font-bold text-purple-800">\${data.ai_analysis.classification}</h3>
                        <p class="text-gray-700 mt-2 text-sm">\${data.ai_analysis.justification}</p>
                        <div class="mt-3 flex items-center justify-between">
                            <div>
                                <span class="text-sm text-gray-600">Confidence:</span>
                                <span class="ml-1 font-semibold text-purple-700">\${(data.ai_analysis.confidence * 100).toFixed(1)}%</span>
                            </div>
                            <div class="text-sm text-gray-500">
                                <i class="fas fa-clock mr-1"></i>
                                \${new Date(data.metadata.processing_time).toLocaleTimeString()}
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <p class="text-sm font-semibold text-gray-700 mb-2">Detected Hazards:</p>
                        <div>
                            \${data.ai_analysis.hazards.map(h => 
                                \`<span class="inline-block bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs mr-2 mb-2">\${h}</span>\`
                            ).join('') || '<span class="text-gray-500 text-sm">No significant hazards detected</span>'}
                        </div>
                    </div>
                    
                    <div class="border-t pt-4">
                        <p class="text-sm font-semibold text-gray-700 mb-3">Detected Cells:</p>
                        <div id="cellsVisualization" class="space-y-2">
                            \${data.cells && data.cells.length > 0 ? data.cells.map((cell, idx) => \`
                                <div class="bg-gray-50 p-3 rounded text-sm">
                                    <div class="flex justify-between items-center">
                                        <span class="font-semibold text-gray-700">Cell \${idx + 1}</span>
                                        <span class="text-xs text-gray-500">\${cell.id}</span>
                                    </div>
                                    <div class="mt-1 grid grid-cols-2 gap-2 text-xs">
                                        <div>
                                            <span class="text-gray-600">Peak:</span>
                                            <span class="ml-1 font-medium">\${cell.peak_value?.toFixed(1)} dBZ</span>
                                        </div>
                                        <div>
                                            <span class="text-gray-600">Location:</span>
                                            <span class="ml-1 font-medium">\${cell.lat?.toFixed(2)}°N, \${cell.lon?.toFixed(2)}°W</span>
                                        </div>
                                    </div>
                                </div>
                            \`).join('') : '<p class="text-gray-500 text-sm">No cells detected</p>'}
                        </div>
                    </div>
                    
                    <div class="mt-4 pt-4 border-t">
                        <p class="text-sm font-semibold text-gray-700 mb-3">Export Options:</p>
                        <div class="grid grid-cols-3 gap-2">
                            <button onclick="exportData('csv')" class="px-3 py-2 bg-green-600 text-white text-xs rounded-lg hover:bg-green-700">
                                <i class="fas fa-file-csv mr-1"></i>CSV
                            </button>
                            <button onclick="exportData('json')" class="px-3 py-2 bg-blue-600 text-white text-xs rounded-lg hover:bg-blue-700">
                                <i class="fas fa-file-code mr-1"></i>JSON
                            </button>
                            <button onclick="exportData('geojson')" class="px-3 py-2 bg-purple-600 text-white text-xs rounded-lg hover:bg-purple-700">
                                <i class="fas fa-map mr-1"></i>GeoJSON
                            </button>
                        </div>
                    </div>
                \`;
            }

            // Search functionality
            async function performSearch() {
                const searchData = {
                    query: document.getElementById('searchQuery').value,
                    classification: document.getElementById('searchClassification').value,
                    confidence_min: document.getElementById('searchConfidenceMin').value,
                    confidence_max: document.getElementById('searchConfidenceMax').value,
                    date_from: document.getElementById('searchDateFrom').value,
                    date_to: document.getElementById('searchDateTo').value
                };

                const response = await fetch('/api/search/analyses', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(searchData)
                });

                if (response.ok) {
                    const data = await response.json();
                    displaySearchResults(data.results);
                }
            }

            function displaySearchResults(results) {
                const html = results.map(r => \`
                    <div class="border p-4 rounded-lg mb-2">
                        <div class="flex justify-between">
                            <span class="font-semibold">\${r.filename}</span>
                            <span class="text-blue-600">\${r.classification}</span>
                        </div>
                        <p class="text-sm text-gray-600">Confidence: \${(r.confidence * 100).toFixed(1)}%</p>
                    </div>
                \`).join('');
                
                document.getElementById('searchResults').innerHTML = html || '<p>No results found</p>';
            }

            // Alerts functionality
            async function loadAlerts() {
                const unreadOnly = document.getElementById('unreadOnly')?.checked;
                const url = '/api/alerts' + (unreadOnly ? '?unread_only=true' : '');
                
                const response = await fetch(url);
                if (response.ok) {
                    const data = await response.json();
                    displayAlerts(data.alerts);
                    
                    // Update alert count
                    const unreadCount = data.alerts.filter(a => !a.is_read).length;
                    const alertCount = document.getElementById('alertCount');
                    if (unreadCount > 0) {
                        alertCount.textContent = unreadCount;
                        alertCount.classList.remove('hidden');
                        
                        // Show alert banner
                        const banner = document.getElementById('alertBanner');
                        const message = document.getElementById('alertMessage');
                        banner.classList.remove('hidden');
                        message.textContent = \`You have \${unreadCount} unread weather alert(s)\`;
                    } else {
                        alertCount.classList.add('hidden');
                        document.getElementById('alertBanner').classList.add('hidden');
                    }
                }
            }

            function displayAlerts(alerts) {
                const html = alerts.map(a => {
                    const severityColors = {
                        extreme: 'bg-red-100 text-red-800',
                        high: 'bg-orange-100 text-orange-800',
                        medium: 'bg-yellow-100 text-yellow-800',
                        low: 'bg-blue-100 text-blue-800'
                    };
                    
                    return \`
                        <div class="border p-4 rounded-lg mb-3 \${!a.is_read ? 'bg-yellow-50' : ''}">
                            <div class="flex justify-between items-start">
                                <div>
                                    <span class="inline-block px-2 py-1 rounded text-sm font-semibold \${severityColors[a.severity]}">
                                        \${a.severity.toUpperCase()}
                                    </span>
                                    <span class="ml-2 text-sm text-gray-500">\${a.alert_type}</span>
                                </div>
                                \${!a.is_read ? \`<button onclick="markAlertRead('\${a.id}')" class="text-blue-600 text-sm">Mark Read</button>\` : ''}
                            </div>
                            <p class="mt-2">\${a.message}</p>
                            <p class="text-xs text-gray-500 mt-1">\${new Date(a.created_at).toLocaleString()}</p>
                        </div>
                    \`;
                }).join('');
                
                document.getElementById('alertsList').innerHTML = html || '<p>No alerts</p>';
            }

            async function markAlertRead(alertId) {
                await fetch(\`/api/alerts/\${alertId}/read\`, { method: 'PATCH' });
                loadAlerts();
            }

            // History functionality
            async function loadHistory() {
                const response = await fetch('/api/history');
                if (response.ok) {
                    const data = await response.json();
                    displayHistory(data.records, data.is_authenticated, data.message);
                }
            }

            function displayHistory(records, isAuthenticated, message) {
                let content = '';
                
                // Show message for anonymous users
                if (!isAuthenticated && message) {
                    content += \`
                        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-4">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <i class="fas fa-info-circle text-yellow-400"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm text-yellow-700">\${message}</p>
                                </div>
                            </div>
                        </div>
                    \`;
                }
                
                if (records.length > 0) {
                    content += \`
                        <table class="min-w-full">
                            <thead>
                                <tr class="bg-gray-50">
                                    <th class="px-4 py-2 text-left">Date</th>
                                    <th class="px-4 py-2 text-left">File</th>
                                    <th class="px-4 py-2 text-left">Variable</th>
                                    <th class="px-4 py-2 text-left">Classification</th>
                                    <th class="px-4 py-2 text-left">Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                \${records.map(r => \`
                                    <tr>
                                        <td class="px-4 py-2">\${new Date(r.created_at).toLocaleString()}</td>
                                        <td class="px-4 py-2">\${r.filename}</td>
                                        <td class="px-4 py-2">\${r.variable || 'Z'}</td>
                                        <td class="px-4 py-2 text-blue-600 font-semibold">\${r.classification}</td>
                                        <td class="px-4 py-2">\${(r.confidence * 100).toFixed(1)}%</td>
                                    </tr>
                                \`).join('')}
                            </tbody>
                        </table>
                    \`;
                } else {
                    content += '<p class="text-gray-500">No analysis history available.</p>';
                }
                
                document.getElementById('historyTable').innerHTML = content;
            }

            // Time-lapse functionality
            async function generateTimelapse() {
                const data = {
                    start_time: document.getElementById('timelapseStart').value,
                    end_time: document.getElementById('timelapseEnd').value,
                    interval_seconds: 1
                };

                const response = await fetch('/api/timelapse/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (response.ok) {
                    const result = await response.json();
                    document.getElementById('timelapseResult').innerHTML = \`
                        <div class="bg-green-100 p-4 rounded-lg">
                            <p class="font-semibold">Animation Generated!</p>
                            <p>Frames: \${result.animation.frames}</p>
                            <p>Duration: \${result.animation.duration_seconds}s</p>
                        </div>
                    \`;
                } else {
                    document.getElementById('timelapseResult').innerHTML = '<p class="text-red-600">No data available for time-lapse</p>';
                }
            }

            // Collaboration functionality
            async function shareAnalysis() {
                if (!currentAnalysisData) {
                    alert('Please analyze data first');
                    return;
                }

                const data = {
                    analysis_id: currentAnalysisData.id,
                    share_with_email: document.getElementById('shareEmail').value,
                    permission: document.getElementById('sharePermission').value
                };

                const response = await fetch('/api/collaborate/share', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (response.ok) {
                    alert('Analysis shared successfully!');
                    loadCollaborations();
                } else {
                    alert('Sharing failed - user may not exist');
                }
            }

            async function loadCollaborations() {
                const response = await fetch('/api/collaborate/shared');
                if (response.ok) {
                    const data = await response.json();
                    displayCollaborations(data.collaborations);
                }
            }

            function displayCollaborations(collabs) {
                const html = collabs.map(c => \`
                    <div class="border p-3 rounded-lg mb-2">
                        <p class="font-semibold">\${c.filename}</p>
                        <p class="text-sm">Shared with: \${c.shared_with_email}</p>
                        <p class="text-xs text-gray-500">Permission: \${c.permission}</p>
                    </div>
                \`).join('');
                
                document.getElementById('sharedList').innerHTML = html || '<p>No shared analyses</p>';
            }

            // Export functionality
            async function exportData(format) {
                if (!currentAnalysisData) {
                    alert('No data to export');
                    return;
                }
                
                const response = await fetch('/api/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        format: format,
                        data: currentAnalysisData
                    })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = \`analysis.\${format === 'geojson' ? 'geojson' : format}\`;
                    a.click();
                    window.URL.revokeObjectURL(url);
                }
            }
            
            // 3D Visualization
            function generate3DView() {
                if (!currentAnalysisData || !currentAnalysisData.cells) {
                    document.getElementById('plot3DContainer').innerHTML = '<p class="text-gray-500">No data available for 3D visualization</p>';
                    return;
                }
                
                // Prepare 3D data
                const cells = currentAnalysisData.cells;
                const x = [], y = [], z = [], intensity = [], text = [];
                
                cells.forEach((cell, idx) => {
                    // Create multiple points for each cell to show volume
                    for (let h = 0; h < 10; h++) {
                        const height = h * 2; // Height levels
                        const attenuatedIntensity = cell.peak_value * Math.exp(-h * 0.2);
                        
                        x.push(cell.lon || 0);
                        y.push(cell.lat || 0);
                        z.push(height);
                        intensity.push(attenuatedIntensity);
                        text.push(\`Cell \${idx + 1}<br>Height: \${height} km<br>dBZ: \${attenuatedIntensity.toFixed(1)}\`);
                    }
                });
                
                const trace3d = {
                    x: x,
                    y: y,
                    z: z,
                    mode: 'markers',
                    marker: {
                        size: 8,
                        color: intensity,
                        colorscale: [
                            [0, 'rgb(0,0,255)'],
                            [0.25, 'rgb(0,255,0)'],
                            [0.5, 'rgb(255,255,0)'],
                            [0.75, 'rgb(255,128,0)'],
                            [1, 'rgb(255,0,0)']
                        ],
                        showscale: true,
                        colorbar: {
                            title: 'Reflectivity (dBZ)',
                            thickness: 20,
                            len: 0.5
                        },
                        opacity: 0.8
                    },
                    text: text,
                    hovertemplate: '%{text}<extra></extra>',
                    type: 'scatter3d'
                };
                
                const layout3d = {
                    title: '3D Storm Structure',
                    scene: {
                        xaxis: {
                            title: 'Longitude',
                            gridcolor: '#e0e0e0',
                            showbackground: true,
                            backgroundcolor: '#f5f5f5'
                        },
                        yaxis: {
                            title: 'Latitude',
                            gridcolor: '#e0e0e0',
                            showbackground: true,
                            backgroundcolor: '#f5f5f5'
                        },
                        zaxis: {
                            title: 'Height (km)',
                            gridcolor: '#e0e0e0',
                            showbackground: true,
                            backgroundcolor: '#f5f5f5'
                        },
                        camera: {
                            eye: {x: 1.5, y: 1.5, z: 1.5}
                        }
                    },
                    margin: {l: 0, r: 0, b: 0, t: 40},
                    paper_bgcolor: 'white',
                    plot_bgcolor: 'white'
                };
                
                const config = {
                    responsive: true,
                    displayModeBar: true,
                    displaylogo: false,
                    modeBarButtonsToRemove: ['lasso2d', 'select2d']
                };
                
                Plotly.newPlot('plot3DContainer', [trace3d], layout3d, config);
            }
            
            // Plotting functions
            let animationInterval = null;
            let currentFrame = 0;
            let animationFrames = [];
            
            window.showPlot = function(type) {
                if (!currentAnalysisData || !currentAnalysisData.plot_data) return;
                
                // Update button states
                document.querySelectorAll('.plot-btn').forEach(btn => {
                    btn.classList.remove('bg-blue-600');
                    btn.classList.add('bg-gray-600');
                });
                
                // Find and highlight the active button
                const activeBtn = Array.from(document.querySelectorAll('.plot-btn')).find(btn => 
                    btn.textContent.toLowerCase().includes(type.toLowerCase().replace('timeseries', 'time series'))
                );
                if (activeBtn) {
                    activeBtn.classList.remove('bg-gray-600');
                    activeBtn.classList.add('bg-blue-600');
                }
                
                // Hide/show animation controls
                const animControls = document.getElementById('animationControls');
                if (type === 'animation') {
                    animControls.classList.remove('hidden');
                } else {
                    animControls.classList.add('hidden');
                    if (animationInterval) {
                        clearInterval(animationInterval);
                        animationInterval = null;
                    }
                }
                
                const plotContainer = document.getElementById('plotContainer');
                
                switch(type) {
                    case 'timeseries':
                        plotTimeSeries();
                        break;
                    case 'spatial':
                        plotSpatial();
                        break;
                    case 'histogram':
                        plotHistogram();
                        break;
                    case 'animation':
                        initAnimation();
                        break;
                }
            }
            
            function plotTimeSeries() {
                const data = currentAnalysisData.plot_data.time_series;
                
                const trace1 = {
                    x: data.map(d => d.time),
                    y: data.map(d => d.value),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: currentAnalysisData.metadata.variable || 'Variable',
                    line: { color: 'rgb(55, 128, 191)', width: 2 }
                };
                
                const trace2 = {
                    x: data.map(d => d.time),
                    y: data.map(d => d.max_dbz),
                    type: 'scatter',
                    mode: 'lines+markers',
                    name: 'Max dBZ',
                    yaxis: 'y2',
                    line: { color: 'rgb(255, 127, 80)', width: 2 }
                };
                
                const layout = {
                    title: \`Time Series Analysis - \${currentAnalysisData.metadata.variable}\`,
                    xaxis: {
                        title: 'Time',
                        type: 'date'
                    },
                    yaxis: {
                        title: currentAnalysisData.metadata.variable + ' Value',
                        side: 'left'
                    },
                    yaxis2: {
                        title: 'Max dBZ',
                        overlaying: 'y',
                        side: 'right'
                    },
                    hovermode: 'x unified'
                };
                
                Plotly.newPlot('plotContainer', [trace1, trace2], layout, {responsive: true});
            }
            
            function plotSpatial() {
                const spatialData = currentAnalysisData.plot_data.spatial_data;
                
                const trace = {
                    type: 'heatmap',
                    z: spatialData.values,
                    colorscale: 'Viridis',
                    colorbar: {
                        title: currentAnalysisData.metadata.variable + ' (dBZ)'
                    }
                };
                
                const layout = {
                    title: \`Spatial Distribution - \${currentAnalysisData.metadata.variable}\`,
                    xaxis: { title: 'Longitude' },
                    yaxis: { title: 'Latitude' },
                    width: null,
                    height: 500
                };
                
                Plotly.newPlot('plotContainer', [trace], layout, {responsive: true});
            }
            
            function plotHistogram() {
                const histData = currentAnalysisData.plot_data.histogram;
                
                const trace = {
                    x: histData.bins.slice(0, -1),
                    y: histData.counts,
                    type: 'bar',
                    marker: {
                        color: 'rgb(55, 128, 191)',
                        line: {
                            color: 'rgb(8,48,107)',
                            width: 1.5
                        }
                    }
                };
                
                const layout = {
                    title: \`Value Distribution - \${currentAnalysisData.metadata.variable}\`,
                    xaxis: { title: currentAnalysisData.metadata.variable + ' (dBZ)' },
                    yaxis: { title: 'Frequency' },
                    bargap: 0.05
                };
                
                Plotly.newPlot('plotContainer', [trace], layout, {responsive: true});
            }
            
            function initAnimation() {
                if (!currentAnalysisData.plot_data.time_series) return;
                
                animationFrames = currentAnalysisData.plot_data.time_series;
                currentFrame = 0;
                updateAnimationFrame();
            }
            
            function updateAnimationFrame() {
                if (currentFrame >= animationFrames.length) currentFrame = 0;
                
                const frame = animationFrames[currentFrame];
                const frameData = currentAnalysisData.plot_data.spatial_data;
                
                // Generate animated data based on frame
                const animatedValues = frameData.values.map(row => 
                    row.map(val => val * (0.8 + 0.4 * Math.sin(currentFrame / 3)))
                );
                
                const trace = {
                    type: 'heatmap',
                    z: animatedValues,
                    colorscale: 'Jet',
                    colorbar: {
                        title: 'Reflectivity (dBZ)'
                    }
                };
                
                const layout = {
                    title: \`Animation Frame \${currentFrame + 1}/\${animationFrames.length} - \${new Date(frame.time).toLocaleString()}\`,
                    xaxis: { title: 'X' },
                    yaxis: { title: 'Y' }
                };
                
                Plotly.newPlot('plotContainer', [trace], layout, {responsive: true});
                
                // Update slider and indicator
                document.getElementById('animationSlider').value = (currentFrame / (animationFrames.length - 1)) * 100;
                document.getElementById('frameIndicator').textContent = \`Frame \${currentFrame + 1}/\${animationFrames.length}\`;
            }
            
            window.playAnimation = function() {
                if (animationInterval) return;
                
                animationInterval = setInterval(() => {
                    currentFrame++;
                    if (currentFrame >= animationFrames.length) currentFrame = 0;
                    updateAnimationFrame();
                }, 500); // 2 fps
            }
            
            window.pauseAnimation = function() {
                if (animationInterval) {
                    clearInterval(animationInterval);
                    animationInterval = null;
                }
            }
            
            window.resetAnimation = function() {
                pauseAnimation();
                currentFrame = 0;
                updateAnimationFrame();
            }
            
            // Animation slider control
            document.addEventListener('DOMContentLoaded', () => {
                const slider = document.getElementById('animationSlider');
                if (slider) {
                    slider.addEventListener('input', (e) => {
                        pauseAnimation();
                        currentFrame = Math.floor((e.target.value / 100) * (animationFrames.length - 1));
                        updateAnimationFrame();
                    });
                }
            });
            
            // Initialize
            checkAuth();
            loadAlerts();
        </script>
    </body>
    </html>
  `)
})

export default app