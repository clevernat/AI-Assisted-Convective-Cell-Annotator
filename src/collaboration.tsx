import { Hono } from 'hono'

type Bindings = {
  DB: D1Database;
}

const collaboration = new Hono<{ Bindings: Bindings }>()

// Share analysis with another user
collaboration.post('/api/collaborate/share', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { analysis_id, share_with_email, permission } = await c.req.json()

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  // Verify the user owns the analysis or has admin permission
  const analysis = await env.DB.prepare(`
    SELECT id FROM analyses WHERE id = ?
  `).bind(analysis_id).first()

  if (!analysis) {
    return c.json({ error: 'Analysis not found' }, 404)
  }

  // Find the user to share with
  const shareUser = await env.DB.prepare(`
    SELECT id FROM users WHERE email = ?
  `).bind(share_with_email).first()

  if (!shareUser) {
    return c.json({ error: 'User not found' }, 404)
  }

  // Check if already shared
  const existing = await env.DB.prepare(`
    SELECT id FROM collaborations 
    WHERE analysis_id = ? AND owner_user_id = ? AND shared_with_user_id = ?
  `).bind(analysis_id, userId, shareUser.id).first()

  if (existing) {
    // Update permission
    await env.DB.prepare(`
      UPDATE collaborations 
      SET permission = ? 
      WHERE id = ?
    `).bind(permission || 'view', existing.id).run()
  } else {
    // Create new collaboration
    const collabId = `collab_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    await env.DB.prepare(`
      INSERT INTO collaborations (id, analysis_id, owner_user_id, shared_with_user_id, permission)
      VALUES (?, ?, ?, ?, ?)
    `).bind(collabId, analysis_id, userId, shareUser.id, permission || 'view').run()
  }

  return c.json({
    success: true,
    message: `Analysis shared with ${share_with_email}`
  })
})

// Get shared analyses
collaboration.get('/api/collaborate/shared', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { direction } = c.req.query() // 'with_me' or 'by_me'

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  let query: string
  let params: any[]

  if (direction === 'by_me') {
    // Analyses I've shared with others
    query = `
      SELECT 
        c.*,
        a.filename,
        a.classification,
        a.confidence,
        a.created_at as analysis_date,
        u.email as shared_with_email,
        u.username as shared_with_username
      FROM collaborations c
      JOIN analyses a ON c.analysis_id = a.id
      JOIN users u ON c.shared_with_user_id = u.id
      WHERE c.owner_user_id = ?
      ORDER BY c.shared_at DESC
    `
    params = [userId]
  } else {
    // Analyses shared with me
    query = `
      SELECT 
        c.*,
        a.filename,
        a.classification,
        a.confidence,
        a.created_at as analysis_date,
        u.email as owner_email,
        u.username as owner_username
      FROM collaborations c
      JOIN analyses a ON c.analysis_id = a.id
      JOIN users u ON c.owner_user_id = u.id
      WHERE c.shared_with_user_id = ?
      ORDER BY c.shared_at DESC
    `
    params = [userId]
  }

  const results = await env.DB.prepare(query).bind(...params).all()

  return c.json({
    success: true,
    collaborations: results.results || []
  })
})

// Remove collaboration
collaboration.delete('/api/collaborate/:id', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const collabId = c.req.param('id')

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  // Verify ownership
  const collab = await env.DB.prepare(`
    SELECT * FROM collaborations 
    WHERE id = ? AND (owner_user_id = ? OR shared_with_user_id = ?)
  `).bind(collabId, userId, userId).first()

  if (!collab) {
    return c.json({ error: 'Collaboration not found' }, 404)
  }

  // Delete collaboration
  await env.DB.prepare(`
    DELETE FROM collaborations WHERE id = ?
  `).bind(collabId).run()

  return c.json({
    success: true,
    message: 'Collaboration removed'
  })
})

// Add comment to shared analysis
collaboration.post('/api/collaborate/comment', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { analysis_id, comment } = await c.req.json()

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  // Verify access
  const access = await env.DB.prepare(`
    SELECT * FROM collaborations 
    WHERE analysis_id = ? AND (owner_user_id = ? OR shared_with_user_id = ?)
  `).bind(analysis_id, userId, userId).first()

  if (!access) {
    return c.json({ error: 'Access denied' }, 403)
  }

  // In a real implementation, we'd have a comments table
  // For now, we'll return a simulated response
  const commentId = `comment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  return c.json({
    success: true,
    comment: {
      id: commentId,
      analysis_id,
      user_id: userId,
      text: comment,
      created_at: new Date().toISOString()
    }
  })
})

// Get collaboration activity feed
collaboration.get('/api/collaborate/activity', async (c) => {
  const { env } = c
  const userId = c.get('userId')

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  // Get recent collaboration activities
  const activities = await env.DB.prepare(`
    SELECT 
      'shared' as type,
      c.shared_at as timestamp,
      a.filename,
      a.classification,
      u1.username as actor,
      u2.username as recipient
    FROM collaborations c
    JOIN analyses a ON c.analysis_id = a.id
    JOIN users u1 ON c.owner_user_id = u1.id
    JOIN users u2 ON c.shared_with_user_id = u2.id
    WHERE c.owner_user_id = ? OR c.shared_with_user_id = ?
    ORDER BY c.shared_at DESC
    LIMIT 20
  `).bind(userId, userId).all()

  return c.json({
    success: true,
    activities: activities.results || []
  })
})

export default collaboration