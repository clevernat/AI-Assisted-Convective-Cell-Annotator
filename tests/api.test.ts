import { describe, it, expect, beforeAll, afterAll } from '@jest/globals'
import { unstable_dev } from 'wrangler'
import type { UnstableDevWorker } from 'wrangler'

describe('A-CLAT API Tests', () => {
  let worker: UnstableDevWorker

  beforeAll(async () => {
    worker = await unstable_dev('src/index.tsx', {
      experimental: { disableExperimentalWarning: true },
    })
  })

  afterAll(async () => {
    await worker.stop()
  })

  // Health Check Tests
  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const resp = await worker.fetch('/api/health')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.status).toBe('healthy')
      expect(data.service).toBe('A-CLAT Enhanced')
      expect(data.version).toBe('2.0.0')
    })
  })

  // Authentication Tests
  describe('Authentication', () => {
    let authToken: string
    const testUser = {
      email: 'test@aclat.com',
      username: 'testuser',
      password: 'TestPassword123!',
      full_name: 'Test User'
    }

    it('should register a new user', async () => {
      const resp = await worker.fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testUser)
      })
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.user.email).toBe(testUser.email)
      expect(data.token).toBeDefined()
      authToken = data.token
    })

    it('should login with valid credentials', async () => {
      const resp = await worker.fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testUser.email,
          password: testUser.password
        })
      })
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.user.email).toBe(testUser.email)
    })

    it('should reject invalid credentials', async () => {
      const resp = await worker.fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testUser.email,
          password: 'WrongPassword'
        })
      })
      
      expect(resp.status).toBe(401)
    })

    it('should get current user with valid token', async () => {
      const resp = await worker.fetch('/api/auth/me', {
        headers: { 
          'Authorization': `Bearer ${authToken}`
        }
      })
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.user.email).toBe(testUser.email)
    })
  })

  // Analysis Tests
  describe('Analysis', () => {
    it('should analyze uploaded file', async () => {
      const formData = new FormData()
      const file = new File(['test data'], 'test.nc', { type: 'application/netcdf' })
      formData.append('file', file)
      formData.append('variable', 'Z')

      const resp = await worker.fetch('/api/analyze', {
        method: 'POST',
        body: formData
      })
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.metadata).toBeDefined()
      expect(data.cells).toBeDefined()
      expect(data.ai_analysis).toBeDefined()
      expect(data.ai_analysis.classification).toBeDefined()
      expect(data.ai_analysis.confidence).toBeGreaterThan(0)
    })

    it('should reject missing file', async () => {
      const formData = new FormData()
      formData.append('variable', 'Z')

      const resp = await worker.fetch('/api/analyze', {
        method: 'POST',
        body: formData
      })
      
      expect(resp.status).toBe(400)
    })
  })

  // Export Tests
  describe('Export', () => {
    const testData = {
      cells: [
        {
          id: 'cell_1',
          lat: 35.2,
          lon: -97.4,
          peak_value: 65.5,
          area_km2: 150,
          vil_kg_m2: 45.3,
          mesh_mm: 35
        }
      ]
    }

    it('should export data as CSV', async () => {
      const resp = await worker.fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format: 'csv',
          data: testData
        })
      })
      
      expect(resp.status).toBe(200)
      expect(resp.headers.get('Content-Type')).toBe('text/csv')
    })

    it('should export data as JSON', async () => {
      const resp = await worker.fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          format: 'json',
          data: testData
        })
      })
      
      expect(resp.status).toBe(200)
      expect(resp.headers.get('Content-Type')).toBe('application/json')
    })
  })

  // Search Tests
  describe('Search', () => {
    it('should search analyses with filters', async () => {
      const resp = await worker.fetch('/api/search/analyses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: 'storm',
          classification: 'Supercell',
          confidence_min: 0.8,
          limit: 10
        })
      })
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.results).toBeDefined()
      expect(data.pagination).toBeDefined()
    })

    it('should get search facets', async () => {
      const resp = await worker.fetch('/api/search/facets')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.facets).toBeDefined()
      expect(data.facets.classifications).toBeDefined()
    })
  })

  // Alert Tests
  describe('Alerts', () => {
    it('should get user alerts', async () => {
      const resp = await worker.fetch('/api/alerts')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.alerts).toBeDefined()
    })

    it('should get alert statistics', async () => {
      const resp = await worker.fetch('/api/alerts/stats')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.statistics).toBeDefined()
    })
  })

  // History Tests
  describe('History', () => {
    it('should get analysis history', async () => {
      const resp = await worker.fetch('/api/history')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.records).toBeDefined()
    })
  })

  // Time-lapse Tests
  describe('Time-lapse', () => {
    it('should generate time-lapse animation', async () => {
      const resp = await worker.fetch('/api/timelapse/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          start_time: '2025-01-01',
          end_time: '2025-01-31',
          interval_seconds: 2
        })
      })
      const data = await resp.json()
      
      expect([200, 404]).toContain(resp.status) // May be 404 if no data
      if (resp.status === 200) {
        expect(data.animation).toBeDefined()
      }
    })

    it('should get animation frames', async () => {
      const resp = await worker.fetch('/api/timelapse/frames?start_time=2025-01-01&end_time=2025-01-31')
      const data = await resp.json()
      
      expect(resp.status).toBe(200)
      expect(data.frames).toBeDefined()
      expect(data.metadata).toBeDefined()
    })
  })

  // Collaboration Tests
  describe('Collaboration', () => {
    it('should require authentication for sharing', async () => {
      const resp = await worker.fetch('/api/collaborate/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis_id: 'test_analysis',
          share_with_email: 'user@example.com',
          permission: 'view'
        })
      })
      
      expect(resp.status).toBe(401)
    })

    it('should get shared analyses', async () => {
      const resp = await worker.fetch('/api/collaborate/shared')
      const data = await resp.json()
      
      expect([200, 401]).toContain(resp.status)
      if (resp.status === 200) {
        expect(data.collaborations).toBeDefined()
      }
    })
  })
})