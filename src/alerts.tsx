import { Hono } from 'hono'

type Bindings = {
  DB: D1Database;
}

type Alert = {
  id: string;
  analysis_id: string;
  user_id?: string;
  alert_type: 'tornado' | 'hail' | 'wind' | 'flood' | 'general';
  severity: 'low' | 'medium' | 'high' | 'extreme';
  message: string;
  location_lat?: number;
  location_lon?: number;
  is_read: boolean;
  sent_at?: string;
  created_at: string;
}

const alerts = new Hono<{ Bindings: Bindings }>()

// Create alert based on analysis
export async function createAlert(
  db: D1Database,
  analysisId: string,
  userId: string | null,
  classification: string,
  hazards: string[],
  statistics: any,
  location: { lat: number; lon: number }
): Promise<void> {
  
  // Determine alert severity and type based on classification
  let alertType: Alert['alert_type'] = 'general'
  let severity: Alert['severity'] = 'low'
  let message = ''

  if (classification === 'Supercell' && hazards.includes('Tornado Possible')) {
    alertType = 'tornado'
    severity = 'extreme'
    message = `TORNADO WARNING: Supercell with strong rotation detected at ${location.lat.toFixed(2)}°N, ${location.lon.toFixed(2)}°W. Seek shelter immediately!`
  } else if (hazards.includes('Large Hail') && statistics.max_mesh_mm > 50) {
    alertType = 'hail'
    severity = statistics.max_mesh_mm > 75 ? 'extreme' : 'high'
    message = `LARGE HAIL WARNING: Hail up to ${statistics.max_mesh_mm.toFixed(0)}mm diameter expected. Seek indoor shelter and protect vehicles.`
  } else if (classification === 'Squall Line' || hazards.includes('Damaging Winds')) {
    alertType = 'wind'
    severity = 'high'
    message = `DAMAGING WIND WARNING: ${classification} producing winds capable of damage. Secure loose objects and avoid windows.`
  } else if (classification === 'MCS' || hazards.includes('Flash Flooding')) {
    alertType = 'flood'
    severity = 'high'
    message = `FLASH FLOOD WARNING: Heavy rainfall from ${classification} may cause rapid flooding. Move to higher ground if in flood-prone areas.`
  } else {
    alertType = 'general'
    severity = 'medium'
    message = `WEATHER ALERT: ${classification} detected with potential for ${hazards.join(', ')}. Monitor conditions closely.`
  }

  const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  await db.prepare(`
    INSERT INTO alerts (id, analysis_id, user_id, alert_type, severity, message, location_lat, location_lon, is_read, sent_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
  `).bind(
    alertId,
    analysisId,
    userId,
    alertType,
    severity,
    message,
    location.lat,
    location.lon
  ).run()
}

// Get user alerts
alerts.get('/api/alerts', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { unread_only, severity, limit } = c.req.query()

  let query = `
    SELECT 
      a.*,
      an.filename,
      an.classification,
      an.confidence
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

  query += ` ORDER BY a.created_at DESC`

  if (limit) {
    query += ` LIMIT ?`
    params.push(parseInt(limit))
  } else {
    query += ` LIMIT 50`
  }

  const results = await env.DB.prepare(query).bind(...params).all()

  return c.json({
    success: true,
    alerts: results.results || []
  })
})

// Mark alert as read
alerts.patch('/api/alerts/:id/read', async (c) => {
  const { env } = c
  const alertId = c.req.param('id')
  const userId = c.get('userId')

  await env.DB.prepare(`
    UPDATE alerts 
    SET is_read = 1 
    WHERE id = ? AND (user_id = ? OR user_id IS NULL)
  `).bind(alertId, userId).run()

  return c.json({ success: true })
})

// Get alert statistics
alerts.get('/api/alerts/stats', async (c) => {
  const { env } = c
  const userId = c.get('userId')

  const stats = await env.DB.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN is_read = 0 THEN 1 ELSE 0 END) as unread,
      SUM(CASE WHEN severity = 'extreme' THEN 1 ELSE 0 END) as extreme,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
    FROM alerts
    WHERE user_id = ? OR user_id IS NULL
  `).bind(userId).first()

  return c.json({
    success: true,
    statistics: stats
  })
})

// Real-time alert subscription (for WebSocket in future)
alerts.get('/api/alerts/subscribe', async (c) => {
  // This would be implemented with WebSockets or Server-Sent Events
  // For now, return polling instructions
  return c.json({
    message: 'Poll /api/alerts endpoint for updates',
    polling_interval_seconds: 30,
    websocket_endpoint: 'wss://your-domain.com/ws/alerts' // Future implementation
  })
})

export default alerts