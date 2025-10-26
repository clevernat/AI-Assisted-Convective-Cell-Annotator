import { Hono } from 'hono'

type Bindings = {
  DB: D1Database;
  R2?: R2Bucket;
}

const timelapse = new Hono<{ Bindings: Bindings }>()

// Generate time-lapse animation data
timelapse.post('/api/timelapse/generate', async (c) => {
  const { env } = c
  const {
    analysis_ids,
    start_time,
    end_time,
    interval_seconds,
    animation_type,
    include_tracks
  } = await c.req.json()

  // Fetch analyses data
  let query = `
    SELECT id, cells_data, statistics, created_at
    FROM analyses
    WHERE 1=1
  `
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

  // Process data for animation
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

  // Generate animation configuration
  const animationConfig = {
    id: `timelapse_${Date.now()}`,
    frames: frames,
    duration_seconds: frames.length * (interval_seconds || 1),
    fps: 10,
    resolution: {
      width: 1920,
      height: 1080
    },
    options: {
      show_tracks: include_tracks || false,
      animation_type: animation_type || 'reflectivity',
      color_scale: 'pyart_NWSRef',
      loop: true
    }
  }

  // Store animation config (would generate actual video in production)
  const animationUrl = await generateAnimationPlaceholder(animationConfig)

  return c.json({
    success: true,
    animation: {
      id: animationConfig.id,
      url: animationUrl,
      frames: frames.length,
      duration_seconds: animationConfig.duration_seconds,
      created_at: new Date().toISOString()
    }
  })
})

// Get animation frames for client-side rendering
timelapse.get('/api/timelapse/frames', async (c) => {
  const { env } = c
  const { start_time, end_time, resolution } = c.req.query()

  const results = await env.DB.prepare(`
    SELECT 
      id,
      created_at as timestamp,
      cells_data,
      statistics,
      classification
    FROM analyses
    WHERE created_at BETWEEN ? AND ?
    ORDER BY created_at ASC
    LIMIT 100
  `).bind(start_time || '2025-01-01', end_time || '2025-12-31').all()

  // Transform data for client-side animation
  const frames = results.results?.map((record: any, index: number) => {
    const cells = JSON.parse(record.cells_data || '[]')
    
    return {
      frame_number: index,
      timestamp: record.timestamp,
      classification: record.classification,
      data: generateFrameData(cells, resolution || 'medium')
    }
  }) || []

  return c.json({
    success: true,
    frames: frames,
    total_frames: frames.length,
    metadata: {
      start_time: frames[0]?.timestamp,
      end_time: frames[frames.length - 1]?.timestamp,
      resolution: resolution || 'medium'
    }
  })
})

// Helper function to generate frame data
function generateFrameData(cells: any[], resolution: string): any {
  const resolutionMap: any = {
    low: { width: 640, height: 360 },
    medium: { width: 1280, height: 720 },
    high: { width: 1920, height: 1080 }
  }

  const res = resolutionMap[resolution] || resolutionMap.medium
  
  // Create grid for heatmap
  const grid = Array(Math.floor(res.height / 10))
    .fill(0)
    .map(() => Array(Math.floor(res.width / 10)).fill(0))

  // Populate grid with cell data
  cells.forEach(cell => {
    if (cell.lat && cell.lon) {
      // Convert lat/lon to grid coordinates
      const x = Math.floor((cell.lon + 110) / 40 * (res.width / 10))
      const y = Math.floor((50 - cell.lat) / 25 * (res.height / 10))
      
      if (x >= 0 && x < grid[0].length && y >= 0 && y < grid.length) {
        grid[y][x] = Math.max(grid[y][x], cell.peak_value || 0)
        
        // Add surrounding pixels for larger storms
        const radius = Math.ceil(Math.sqrt(cell.area_km2 || 100) / 10)
        for (let dy = -radius; dy <= radius; dy++) {
          for (let dx = -radius; dx <= radius; dx++) {
            const nx = x + dx
            const ny = y + dy
            if (nx >= 0 && nx < grid[0].length && ny >= 0 && ny < grid.length) {
              const distance = Math.sqrt(dx * dx + dy * dy)
              const value = (cell.peak_value || 0) * Math.exp(-distance / radius)
              grid[ny][nx] = Math.max(grid[ny][nx], value)
            }
          }
        }
      }
    }
  })

  return {
    grid: grid,
    max_value: Math.max(...grid.flat()),
    cell_positions: cells.map(c => ({
      x: (c.lon + 110) / 40 * res.width,
      y: (50 - c.lat) / 25 * res.height,
      value: c.peak_value
    }))
  }
}

// Generate placeholder animation URL
async function generateAnimationPlaceholder(config: any): Promise<string> {
  // In production, this would generate actual video file
  // For now, return a data URL with animation metadata
  const metadata = {
    type: 'timelapse',
    frames: config.frames.length,
    duration: config.duration_seconds,
    generated_at: new Date().toISOString()
  }
  
  return `data:application/json;base64,${Buffer.from(JSON.stringify(metadata)).toString('base64')}`
}

export default timelapse