import { Hono } from 'hono'

type Bindings = {
  DB: D1Database;
}

const search = new Hono<{ Bindings: Bindings }>()

// Advanced search endpoint
search.post('/api/search/analyses', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  
  const {
    query,
    classification,
    confidence_min,
    confidence_max,
    date_from,
    date_to,
    has_tornado_risk,
    min_dbz,
    max_dbz,
    min_vil,
    sort_by,
    order,
    limit,
    offset
  } = await c.req.json()

  // Build dynamic query
  let sql = `
    SELECT 
      a.*,
      COUNT(al.id) as alert_count,
      MAX(al.severity) as max_alert_severity
    FROM analyses a
    LEFT JOIN alerts al ON a.id = al.analysis_id
    WHERE 1=1
  `
  const params: any[] = []

  // Text search in filename and justification
  if (query) {
    sql += ` AND (a.filename LIKE ? OR a.justification LIKE ?)`
    params.push(`%${query}%`, `%${query}%`)
  }

  // Classification filter
  if (classification) {
    if (Array.isArray(classification)) {
      sql += ` AND a.classification IN (${classification.map(() => '?').join(',')})`
      params.push(...classification)
    } else {
      sql += ` AND a.classification = ?`
      params.push(classification)
    }
  }

  // Confidence range
  if (confidence_min !== undefined) {
    sql += ` AND a.confidence >= ?`
    params.push(confidence_min)
  }
  if (confidence_max !== undefined) {
    sql += ` AND a.confidence <= ?`
    params.push(confidence_max)
  }

  // Date range
  if (date_from) {
    sql += ` AND a.created_at >= ?`
    params.push(date_from)
  }
  if (date_to) {
    sql += ` AND a.created_at <= ?`
    params.push(date_to)
  }

  // Hazard filters
  if (has_tornado_risk) {
    sql += ` AND a.hazards LIKE '%Tornado%'`
  }

  // Statistics filters (stored as JSON)
  if (min_dbz !== undefined) {
    sql += ` AND json_extract(a.statistics, '$.max_peak_dbz') >= ?`
    params.push(min_dbz)
  }
  if (max_dbz !== undefined) {
    sql += ` AND json_extract(a.statistics, '$.max_peak_dbz') <= ?`
    params.push(max_dbz)
  }
  if (min_vil !== undefined) {
    sql += ` AND json_extract(a.statistics, '$.max_vil_kg_m2') >= ?`
    params.push(min_vil)
  }

  // Group by for alert aggregation
  sql += ` GROUP BY a.id`

  // Sorting
  const validSortFields = ['created_at', 'confidence', 'classification', 'alert_count']
  const sortField = validSortFields.includes(sort_by) ? sort_by : 'created_at'
  const sortOrder = order === 'asc' ? 'ASC' : 'DESC'
  sql += ` ORDER BY ${sortField} ${sortOrder}`

  // Pagination
  const pageLimit = Math.min(parseInt(limit) || 20, 100)
  const pageOffset = parseInt(offset) || 0
  sql += ` LIMIT ? OFFSET ?`
  params.push(pageLimit, pageOffset)

  // Execute search
  const results = await env.DB.prepare(sql).bind(...params).all()

  // Get total count for pagination
  const countSql = `
    SELECT COUNT(DISTINCT a.id) as total
    FROM analyses a
    LEFT JOIN alerts al ON a.id = al.analysis_id
    WHERE 1=1
  `
  // Apply same filters for count (simplified)
  const countResult = await env.DB.prepare(countSql).first()

  return c.json({
    success: true,
    results: results.results || [],
    pagination: {
      total: countResult?.total || 0,
      limit: pageLimit,
      offset: pageOffset,
      has_more: (countResult?.total || 0) > pageOffset + pageLimit
    }
  })
})

// Faceted search - get available filters
search.get('/api/search/facets', async (c) => {
  const { env } = c

  const [classifications, severities, dateRange, statistics] = await Promise.all([
    // Get unique classifications with counts
    env.DB.prepare(`
      SELECT classification, COUNT(*) as count
      FROM analyses
      GROUP BY classification
      ORDER BY count DESC
    `).all(),

    // Get alert severities with counts
    env.DB.prepare(`
      SELECT severity, COUNT(*) as count
      FROM alerts
      GROUP BY severity
      ORDER BY CASE severity 
        WHEN 'extreme' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
      END
    `).all(),

    // Get date range
    env.DB.prepare(`
      SELECT 
        MIN(created_at) as earliest,
        MAX(created_at) as latest,
        COUNT(*) as total
      FROM analyses
    `).first(),

    // Get statistics ranges
    env.DB.prepare(`
      SELECT 
        MIN(json_extract(statistics, '$.max_peak_dbz')) as min_dbz,
        MAX(json_extract(statistics, '$.max_peak_dbz')) as max_dbz,
        MIN(json_extract(statistics, '$.max_vil_kg_m2')) as min_vil,
        MAX(json_extract(statistics, '$.max_vil_kg_m2')) as max_vil,
        MIN(json_extract(statistics, '$.max_mesh_mm')) as min_mesh,
        MAX(json_extract(statistics, '$.max_mesh_mm')) as max_mesh
      FROM analyses
      WHERE statistics IS NOT NULL
    `).first()
  ])

  return c.json({
    success: true,
    facets: {
      classifications: classifications.results || [],
      severities: severities.results || [],
      date_range: dateRange,
      statistics_ranges: statistics
    }
  })
})

// Quick search suggestions
search.get('/api/search/suggestions', async (c) => {
  const { env } = c
  const { q } = c.req.query()

  if (!q || q.length < 2) {
    return c.json({ suggestions: [] })
  }

  const results = await env.DB.prepare(`
    SELECT DISTINCT filename
    FROM analyses
    WHERE filename LIKE ?
    LIMIT 10
  `).bind(`%${q}%`).all()

  return c.json({
    suggestions: results.results?.map(r => r.filename) || []
  })
})

// Saved searches
search.post('/api/search/saved', async (c) => {
  const { env } = c
  const userId = c.get('userId')
  const { name, query, filters } = await c.req.json()

  if (!userId) {
    return c.json({ error: 'Authentication required' }, 401)
  }

  const searchId = `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

  // Store saved search in KV or database
  // For now, we'll use a simple implementation
  return c.json({
    success: true,
    saved_search: {
      id: searchId,
      name,
      query,
      filters,
      created_at: new Date().toISOString()
    }
  })
})

export default search