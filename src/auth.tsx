import { Hono } from 'hono'
import { sign, verify } from 'hono/jwt'
import { setCookie, getCookie } from 'hono/cookie'
import * as bcrypt from 'bcryptjs'

type Bindings = {
  DB: D1Database;
  JWT_SECRET: string;
}

const auth = new Hono<{ Bindings: Bindings }>()

// Generate JWT token
async function generateToken(userId: string, email: string, secret: string): Promise<string> {
  const payload = {
    sub: userId,
    email: email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
  }
  return await sign(payload, secret)
}

// Verify JWT token
async function verifyToken(token: string, secret: string) {
  try {
    const payload = await verify(token, secret)
    return payload
  } catch (error) {
    return null
  }
}

// Hash password
async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(10)
  return await bcrypt.hash(password, salt)
}

// Verify password
async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash)
}

// Register endpoint
auth.post('/api/auth/register', async (c) => {
  const { env } = c
  const { email, username, password, full_name } = await c.req.json()

  // Validate input
  if (!email || !username || !password) {
    return c.json({ error: 'Missing required fields' }, 400)
  }

  // Check if user exists
  const existingUser = await env.DB.prepare(
    'SELECT id FROM users WHERE email = ? OR username = ?'
  ).bind(email, username).first()

  if (existingUser) {
    return c.json({ error: 'User already exists' }, 409)
  }

  // Hash password
  const passwordHash = await hashPassword(password)
  const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const apiKey = `api_${Math.random().toString(36).substr(2, 32)}`

  // Create user
  await env.DB.prepare(`
    INSERT INTO users (id, email, username, password_hash, full_name, api_key, is_active)
    VALUES (?, ?, ?, ?, ?, ?, 1)
  `).bind(userId, email, username, passwordHash, full_name || null, apiKey).run()

  // Generate token
  const token = await generateToken(userId, email, env.JWT_SECRET || 'default-secret')

  // Create session
  const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

  await env.DB.prepare(`
    INSERT INTO sessions (id, user_id, token, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionId, userId, token, expiresAt).run()

  // Set cookie
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
      id: userId,
      email,
      username,
      full_name,
      api_key
    },
    token
  })
})

// Login endpoint
auth.post('/api/auth/login', async (c) => {
  const { env } = c
  const { email, password } = await c.req.json()

  if (!email || !password) {
    return c.json({ error: 'Missing credentials' }, 400)
  }

  // Find user
  const user = await env.DB.prepare(`
    SELECT id, email, username, password_hash, full_name, role, api_key, is_active
    FROM users WHERE email = ? OR username = ?
  `).bind(email, email).first()

  if (!user || !user.is_active) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  // Verify password
  const isValid = await verifyPassword(password, user.password_hash as string)
  if (!isValid) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  // Update last login
  await env.DB.prepare(`
    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
  `).bind(user.id).run()

  // Generate token
  const token = await generateToken(user.id as string, user.email as string, env.JWT_SECRET || 'default-secret')

  // Create session
  const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

  await env.DB.prepare(`
    INSERT INTO sessions (id, user_id, token, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionId, user.id, token, expiresAt).run()

  // Set cookie
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
      role: user.role,
      api_key: user.api_key
    },
    token
  })
})

// Logout endpoint
auth.post('/api/auth/logout', async (c) => {
  const { env } = c
  const token = getCookie(c, 'auth_token')

  if (token) {
    // Delete session
    await env.DB.prepare(`
      DELETE FROM sessions WHERE token = ?
    `).bind(token).run()
  }

  // Clear cookie
  setCookie(c, 'auth_token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 0,
    path: '/'
  })

  return c.json({ success: true, message: 'Logged out successfully' })
})

// Get current user
auth.get('/api/auth/me', async (c) => {
  const { env } = c
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')

  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  // Verify token
  const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401)
  }

  // Get user
  const user = await env.DB.prepare(`
    SELECT id, email, username, full_name, role, api_key, created_at
    FROM users WHERE id = ?
  `).bind(payload.sub).first()

  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  return c.json({
    success: true,
    user
  })
})

// Middleware to protect routes
export async function requireAuth(c: any, next: any) {
  const { env } = c
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')

  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401)
  }

  const payload = await verifyToken(token, env.JWT_SECRET || 'default-secret')
  if (!payload) {
    return c.json({ error: 'Invalid token' }, 401)
  }

  // Check if session is valid
  const session = await env.DB.prepare(`
    SELECT * FROM sessions 
    WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
  `).bind(token).first()

  if (!session) {
    return c.json({ error: 'Session expired' }, 401)
  }

  // Add user to context
  c.set('userId', payload.sub)
  c.set('userEmail', payload.email)

  await next()
}

export default auth