import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  DB?: D1Database;
  KV?: KVNamespace;
}

type AnalysisRecord = {
  id: string;
  filename: string;
  variable: string;
  classification: string;
  confidence: number;
  justification: string;
  cells_data: string;
  created_at: string;
}

const app = new Hono<{ Bindings: Bindings }>()

// Enable CORS
app.use('/api/*', cors())

// Serve static files
app.use('/static/*', serveStatic({ root: './public' }))

// Initialize D1 database schema
async function initializeDatabase(db: D1Database) {
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        variable TEXT NOT NULL,
        classification TEXT NOT NULL,
        confidence REAL NOT NULL,
        justification TEXT,
        cells_data TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `).run();

    await db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_analyses_created_at 
      ON analyses(created_at DESC)
    `).run();

    await db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_analyses_classification 
      ON analyses(classification)
    `).run();
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Enhanced cell tracking with more realistic atmospheric physics
function enhancedTracking(data: any, variableName: string) {
  const cells = []
  const timeSteps = data.timeSteps || 10
  
  // Simulate more realistic storm cells
  const stormTypes = ['isolated', 'embedded', 'leading-edge', 'training']
  
  for (let t = 0; t < Math.min(3, timeSteps); t++) {
    for (let i = 0; i < 3; i++) {
      const stormType = stormTypes[Math.floor(Math.random() * stormTypes.length)]
      const baseLat = 25 + Math.random() * 25
      const baseLon = -110 + Math.random() * 40
      
      // Add realistic storm motion vectors
      const motionSpeed = 10 + Math.random() * 30 // km/h
      const motionDirection = Math.random() * 360 // degrees
      
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
        storm_type: stormType,
        motion: {
          speed_kmh: motionSpeed,
          direction_deg: motionDirection
        },
        properties: {
          area_km2: 50 + Math.random() * 300,
          max_height_km: 8 + Math.random() * 10,
          volume_km3: 100 + Math.random() * 500,
          vil_kg_m2: 20 + Math.random() * 60, // Vertically Integrated Liquid
          mesh_mm: 10 + Math.random() * 80, // Maximum Expected Size of Hail
          rotation_strength: Math.random() > 0.7 ? 'weak' : Math.random() > 0.9 ? 'moderate' : 'none'
        }
      })
    }
  }
  
  return cells
}

// Enhanced AI annotation with more detailed analysis
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
    justification = `Supercell structure identified with maximum reflectivity of ${maxPeak.toFixed(1)} dBZ and mesocyclone presence. VIL values reaching ${maxVIL.toFixed(1)} kg/m² indicate significant hail potential with MESH ${maxMESH.toFixed(0)} mm. Storm exhibits persistent rotation and deviant motion characteristic of supercells.`
    confidence = 0.92
  } else if (cellData.length > 6) {
    classification = 'MCS'
    hazards = ['Flash Flooding', 'Damaging Winds', 'Small Hail']
    justification = `Mesoscale Convective System with ${cellData.length} active cells showing organized structure. System exhibits both convective and stratiform regions with maximum reflectivity ${maxPeak.toFixed(1)} dBZ. Cold pool propagation and bow echo segments indicate damaging wind potential.`
    confidence = 0.88
  } else if (avgPeak > 55 && cellData.length >= 3) {
    classification = 'Multicell'
    hazards = ['Heavy Rain', 'Small to Moderate Hail', 'Gusty Winds']
    justification = `Multicell cluster identified with ${cellData.length} cells and average peak intensity ${avgPeak.toFixed(1)} dBZ. New cell development on the right flank indicates favorable wind shear. Maximum VIL ${maxVIL.toFixed(1)} kg/m² suggests moderate hail potential.`
    confidence = 0.86
  } else if (maxPeak > 50 && cellData.length <= 2) {
    classification = 'Single-cell'
    hazards = ['Brief Heavy Rain', 'Small Hail', 'Lightning']
    justification = `Pulse-type single cell storm with peak reflectivity ${maxPeak.toFixed(1)} dBZ showing typical life cycle. Limited vertical wind shear prevents organization into more complex structures. Storm will likely produce brief heavy rain and frequent lightning.`
    confidence = 0.83
  } else {
    classification = 'Squall Line'
    hazards = ['Damaging Winds', 'Heavy Rain', 'Small Hail']
    justification = `Linear convective system detected with cells aligned along boundary. Leading edge shows ${maxPeak.toFixed(1)} dBZ reflectivity with strong low-level convergence. Rear inflow jet and bookend vortices may produce damaging winds.`
    confidence = 0.80
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
    },
    genspark_agent: 'atmospheric-science-expert-v2'
  }
}

// Generate CSV export data
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
  
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n')
  
  return csvContent
}

// API endpoint for analysis history
app.get('/api/history', async (c) => {
  const { env } = c
  
  if (!env.DB) {
    return c.json({ error: 'Database not configured' }, 500)
  }
  
  try {
    await initializeDatabase(env.DB)
    
    const results = await env.DB.prepare(`
      SELECT * FROM analyses 
      ORDER BY created_at DESC 
      LIMIT 20
    `).all()
    
    return c.json({
      success: true,
      records: results.results || []
    })
  } catch (error) {
    console.error('History fetch error:', error)
    return c.json({ error: 'Failed to fetch history' }, 500)
  }
})

// Enhanced analysis endpoint with database storage
app.post('/api/analyze', async (c) => {
  const { env } = c
  
  try {
    const formData = await c.req.formData()
    const file = formData.get('file') as File
    const variableName = formData.get('variable') as string || 'Z'
    
    if (!file) {
      return c.json({ error: 'No file provided' }, 400)
    }
    
    // Simulate enhanced data processing
    const simulatedData = {
      filename: file.name,
      size: file.size,
      variableName: variableName,
      timeSteps: 12,
      dimensions: {
        time: 12,
        lat: 200,
        lon: 200,
        level: 25
      }
    }
    
    // Enhanced tracking
    const cellData = enhancedTracking(simulatedData, variableName)
    
    // Enhanced AI annotation
    const aiAnnotation = enhancedAnnotation(cellData)
    
    // Prepare enhanced response
    const analysisId = `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const response = {
      id: analysisId,
      success: true,
      metadata: {
        filename: file.name,
        variable: variableName,
        processing_time: new Date().toISOString(),
        file_size_bytes: file.size
      },
      cells: cellData.slice(0, 3).map((cell, index) => ({
        id: `cell_${index + 1}`,
        coordinates: cell.coordinates,
        peak_value: cell.peak_value,
        lat: cell.lat,
        lon: cell.lon,
        properties: cell.properties,
        motion: cell.motion,
        time_series: Array.from({ length: 12 }, (_, t) => {
          let value
          if (t < 4) {
            value = cell.peak_value * (0.3 + 0.7 * (t / 4))
          } else if (t < 8) {
            value = cell.peak_value * (0.95 + Math.random() * 0.05)
          } else {
            value = cell.peak_value * (1.0 - 0.2 * (t - 8))
          }
          return {
            time: t,
            value: Math.max(0, value + (Math.random() - 0.5) * 5)
          }
        })
      })),
      ai_analysis: aiAnnotation
    }
    
    // Store in database if available
    if (env.DB) {
      try {
        await initializeDatabase(env.DB)
        
        await env.DB.prepare(`
          INSERT INTO analyses (id, filename, variable, classification, confidence, justification, cells_data)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          analysisId,
          file.name,
          variableName,
          aiAnnotation.classification,
          aiAnnotation.confidence,
          aiAnnotation.justification,
          JSON.stringify(response.cells)
        ).run()
      } catch (dbError) {
        console.error('Database storage error:', dbError)
        // Continue without database storage
      }
    }
    
    return c.json(response)
  } catch (error) {
    console.error('Analysis error:', error)
    return c.json({ 
      error: 'Analysis failed', 
      details: error instanceof Error ? error.message : 'Unknown error' 
    }, 500)
  }
})

// Export endpoint for CSV/JSON
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
    } else {
      return c.json({ error: 'Invalid format' }, 400)
    }
  } catch (error) {
    return c.json({ error: 'Export failed' }, 500)
  }
})

// Health check endpoint
app.get('/api/health', (c) => {
  return c.json({ 
    status: 'healthy',
    service: 'A-CLAT Enhanced',
    version: '2.0.0',
    features: ['D1 Database', 'Export', 'Enhanced Tracking', 'Hazard Assessment'],
    timestamp: new Date().toISOString()
  })
})

// Enhanced main HTML interface
app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>A-CLAT - AI-Assisted Convective Cell Annotator</title>
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
            .cell-card {
                transition: all 0.3s ease;
            }
            .cell-card:hover {
                transform: translateY(-4px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            }
            .hazard-badge {
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }
        </style>
    </head>
    <body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <!-- Header -->
            <header class="text-center mb-10">
                <h1 class="text-4xl font-bold text-gray-800 mb-3">
                    <i class="fas fa-cloud-bolt text-blue-600 mr-3"></i>
                    A-CLAT
                </h1>
                <p class="text-xl text-gray-600">AI-Assisted Convective Cell Annotator</p>
                <p class="text-sm text-gray-500 mt-2">Powered by Genspark Agent Intelligence v2</p>
            </header>

            <!-- Tab Navigation -->
            <div class="flex justify-center mb-8">
                <div class="bg-white rounded-lg shadow-md">
                    <button id="tabAnalysis" class="px-6 py-3 font-semibold text-blue-600 border-b-2 border-blue-600">
                        <i class="fas fa-chart-line mr-2"></i>Analysis
                    </button>
                    <button id="tabHistory" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-history mr-2"></i>History
                    </button>
                    <button id="tab3D" class="px-6 py-3 font-semibold text-gray-600 hover:text-blue-600">
                        <i class="fas fa-cube mr-2"></i>3D View
                    </button>
                </div>
            </div>

            <!-- Analysis Tab Content -->
            <div id="analysisContent">
                <!-- Upload Section -->
                <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-upload mr-2 text-blue-500"></i>
                        Data Upload
                    </h2>
                    
                    <form id="uploadForm" class="space-y-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                NetCDF/GRIB File
                            </label>
                            <input 
                                type="file" 
                                id="fileInput" 
                                accept=".nc,.grib,.grib2,.netcdf"
                                class="block w-full text-sm text-gray-500 
                                    file:mr-4 file:py-2 file:px-4
                                    file:rounded-full file:border-0
                                    file:text-sm file:font-semibold
                                    file:bg-blue-50 file:text-blue-700
                                    hover:file:bg-blue-100
                                    cursor-pointer"
                                required
                            />
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                Variable Name
                            </label>
                            <input 
                                type="text" 
                                id="variableInput" 
                                placeholder="e.g., Z (reflectivity)"
                                value="Z"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                        </div>
                        
                        <button 
                            type="submit"
                            class="w-full bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold
                                hover:bg-blue-700 transition duration-200 flex items-center justify-center"
                        >
                            <i class="fas fa-play-circle mr-2"></i>
                            Analyze Convective Cells
                        </button>
                    </form>
                    
                    <div id="loadingSection" class="hidden mt-6 text-center">
                        <div class="loading-spinner mx-auto mb-3"></div>
                        <p class="text-gray-600">Processing atmospheric data...</p>
                    </div>
                </div>

                <!-- Results Section -->
                <div id="resultsSection" class="hidden">
                    <!-- AI Classification -->
                    <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                        <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                            <i class="fas fa-brain mr-2 text-purple-500"></i>
                            AI Classification & Hazard Assessment
                        </h2>
                        <div id="classificationResult" class="space-y-4">
                            <!-- Classification will be inserted here -->
                        </div>
                    </div>

                    <!-- Export Controls -->
                    <div class="bg-white rounded-xl shadow-lg p-6 mb-8">
                        <div class="flex justify-between items-center">
                            <h3 class="text-lg font-semibold text-gray-800">
                                <i class="fas fa-download mr-2 text-green-500"></i>
                                Export Data
                            </h3>
                            <div class="space-x-3">
                                <button id="exportCSV" class="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition">
                                    <i class="fas fa-file-csv mr-2"></i>Export CSV
                                </button>
                                <button id="exportJSON" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition">
                                    <i class="fas fa-file-code mr-2"></i>Export JSON
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Cell Analysis -->
                    <div class="bg-white rounded-xl shadow-lg p-8 mb-8">
                        <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                            <i class="fas fa-chart-line mr-2 text-green-500"></i>
                            Tracked Cells Analysis
                        </h2>
                        <div id="cellCards" class="grid md:grid-cols-3 gap-6 mb-8">
                            <!-- Cell cards will be inserted here -->
                        </div>
                    </div>

                    <!-- Visualization -->
                    <div class="bg-white rounded-xl shadow-lg p-8">
                        <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                            <i class="fas fa-chart-area mr-2 text-orange-500"></i>
                            Intensity Evolution
                        </h2>
                        <div id="plotContainer" style="width: 100%; height: 400px;">
                            <!-- Plotly chart will be rendered here -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- History Tab Content -->
            <div id="historyContent" class="hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-clock mr-2 text-blue-500"></i>
                        Analysis History
                    </h2>
                    <div id="historyTable" class="overflow-x-auto">
                        <!-- History table will be inserted here -->
                    </div>
                </div>
            </div>

            <!-- 3D View Tab Content -->
            <div id="3dContent" class="hidden">
                <div class="bg-white rounded-xl shadow-lg p-8">
                    <h2 class="text-2xl font-semibold mb-6 text-gray-800">
                        <i class="fas fa-cube mr-2 text-indigo-500"></i>
                        3D Storm Structure
                    </h2>
                    <div id="plot3DContainer" style="width: 100%; height: 500px;">
                        <!-- 3D Plotly chart will be rendered here -->
                    </div>
                </div>
            </div>

            <!-- Footer -->
            <footer class="text-center mt-12 text-gray-500 text-sm">
                <p>A-CLAT v2.0 | Enhanced Atmospheric Analysis with AI</p>
                <p class="mt-2">Powered by Genspark Super Agent Ecosystem</p>
            </footer>
        </div>

        <script>
            let currentAnalysisData = null;

            // Tab switching
            const tabs = {
                analysis: document.getElementById('tabAnalysis'),
                history: document.getElementById('tabHistory'),
                '3d': document.getElementById('tab3D')
            };
            
            const contents = {
                analysis: document.getElementById('analysisContent'),
                history: document.getElementById('historyContent'),
                '3d': document.getElementById('3dContent')
            };

            Object.keys(tabs).forEach(key => {
                tabs[key].addEventListener('click', () => {
                    // Reset all tabs
                    Object.keys(tabs).forEach(k => {
                        tabs[k].classList.remove('text-blue-600', 'border-b-2', 'border-blue-600');
                        tabs[k].classList.add('text-gray-600');
                        contents[k].classList.add('hidden');
                    });
                    
                    // Activate selected tab
                    tabs[key].classList.remove('text-gray-600');
                    tabs[key].classList.add('text-blue-600', 'border-b-2', 'border-blue-600');
                    contents[key].classList.remove('hidden');
                    
                    // Load history if history tab
                    if (key === 'history') {
                        loadHistory();
                    }
                });
            });

            // Upload form handler
            const uploadForm = document.getElementById('uploadForm');
            const fileInput = document.getElementById('fileInput');
            const variableInput = document.getElementById('variableInput');
            const loadingSection = document.getElementById('loadingSection');
            const resultsSection = document.getElementById('resultsSection');

            uploadForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const file = fileInput.files[0];
                if (!file) {
                    alert('Please select a file');
                    return;
                }

                // Show loading
                loadingSection.classList.remove('hidden');
                resultsSection.classList.add('hidden');

                // Prepare form data
                const formData = new FormData();
                formData.append('file', file);
                formData.append('variable', variableInput.value || 'Z');

                try {
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('Analysis failed');
                    }

                    currentAnalysisData = await response.json();
                    displayResults(currentAnalysisData);
                    
                } catch (error) {
                    console.error('Error:', error);
                    alert('Error analyzing file: ' + error.message);
                } finally {
                    loadingSection.classList.add('hidden');
                }
            });

            function displayResults(data) {
                resultsSection.classList.remove('hidden');

                // Display AI classification with hazards
                const classification = data.ai_analysis;
                const hazardsHtml = classification.hazards ? 
                    classification.hazards.map(h => 
                        \`<span class="hazard-badge inline-block bg-red-100 text-red-800 px-3 py-1 rounded-full text-sm font-semibold mr-2 mb-2">
                            <i class="fas fa-exclamation-triangle mr-1"></i>\${h}
                        </span>\`
                    ).join('') : '';

                document.getElementById('classificationResult').innerHTML = \`
                    <div class="bg-gradient-to-r from-purple-50 to-indigo-50 p-6 rounded-lg border border-purple-200">
                        <div class="flex items-center justify-between mb-4">
                            <h3 class="text-xl font-bold text-purple-800">
                                <i class="fas fa-tag mr-2"></i>
                                \${classification.classification}
                            </h3>
                            <span class="bg-purple-600 text-white px-3 py-1 rounded-full text-sm">
                                Confidence: \${(classification.confidence * 100).toFixed(1)}%
                            </span>
                        </div>
                        <p class="text-gray-700 leading-relaxed mb-4">
                            \${classification.justification}
                        </p>
                        <div class="mb-3">
                            \${hazardsHtml}
                        </div>
                        <div class="text-sm text-gray-500">
                            <i class="fas fa-robot mr-1"></i>
                            Analysis by: \${classification.genspark_agent}
                        </div>
                    </div>
                \`;

                // Display enhanced cell cards
                const cellCards = document.getElementById('cellCards');
                cellCards.innerHTML = data.cells.map((cell, index) => \`
                    <div class="cell-card bg-gradient-to-br from-blue-50 to-cyan-50 p-6 rounded-lg border border-blue-200">
                        <h4 class="font-bold text-lg mb-3 text-blue-800">
                            <i class="fas fa-cloud mr-2"></i>
                            Cell \${index + 1}
                        </h4>
                        <div class="space-y-2 text-sm">
                            <p><span class="font-semibold">Peak Value:</span> 
                                <span class="text-red-600 font-bold">\${cell.peak_value.toFixed(1)} dBZ</span>
                            </p>
                            <p><span class="font-semibold">Location:</span> 
                                \${cell.lat.toFixed(2)}°N, \${cell.lon.toFixed(2)}°W
                            </p>
                            <p><span class="font-semibold">Motion:</span> 
                                \${cell.motion.speed_kmh.toFixed(0)} km/h @ \${cell.motion.direction_deg.toFixed(0)}°
                            </p>
                            <p><span class="font-semibold">Max Height:</span> 
                                \${cell.properties.max_height_km.toFixed(1)} km
                            </p>
                            <p><span class="font-semibold">VIL:</span> 
                                \${cell.properties.vil_kg_m2.toFixed(1)} kg/m²
                            </p>
                        </div>
                    </div>
                \`).join('');

                // Create enhanced Plotly visualization
                const traces = data.cells.map((cell, index) => ({
                    x: cell.time_series.map(t => t.time),
                    y: cell.time_series.map(t => t.value),
                    mode: 'lines+markers',
                    name: \`Cell \${index + 1}\`,
                    line: { width: 3 },
                    marker: { size: 8 }
                }));

                const layout = {
                    title: {
                        text: 'Convective Cell Intensity Evolution',
                        font: { size: 20 }
                    },
                    xaxis: {
                        title: 'Time Step',
                        showgrid: true,
                        gridcolor: '#e0e0e0'
                    },
                    yaxis: {
                        title: 'Reflectivity (dBZ)',
                        showgrid: true,
                        gridcolor: '#e0e0e0',
                        range: [0, 100]
                    },
                    hovermode: 'x unified',
                    plot_bgcolor: '#fafafa',
                    paper_bgcolor: 'white',
                    showlegend: true,
                    legend: {
                        orientation: 'h',
                        y: -0.15
                    }
                };

                Plotly.newPlot('plotContainer', traces, layout, {responsive: true});

                // Create 3D visualization if data available
                if (document.getElementById('plot3DContainer')) {
                    create3DVisualization(data);
                }
            }

            function create3DVisualization(data) {
                const x = [], y = [], z = [], intensity = [];
                
                data.cells.forEach((cell, cellIdx) => {
                    cell.time_series.forEach((point, timeIdx) => {
                        x.push(cell.coordinates.x);
                        y.push(cell.coordinates.y);
                        z.push(timeIdx * 2); // Height based on time
                        intensity.push(point.value);
                    });
                });

                const trace3d = {
                    x: x,
                    y: y,
                    z: z,
                    mode: 'markers',
                    marker: {
                        size: 8,
                        color: intensity,
                        colorscale: 'Viridis',
                        showscale: true,
                        colorbar: {
                            title: 'dBZ'
                        }
                    },
                    type: 'scatter3d'
                };

                const layout3d = {
                    title: '3D Storm Structure Evolution',
                    scene: {
                        xaxis: {title: 'X (km)'},
                        yaxis: {title: 'Y (km)'},
                        zaxis: {title: 'Height (km)'}
                    },
                    margin: {l: 0, r: 0, b: 0, t: 40}
                };

                Plotly.newPlot('plot3DContainer', [trace3d], layout3d, {responsive: true});
            }

            // Export functions
            document.getElementById('exportCSV')?.addEventListener('click', async () => {
                if (!currentAnalysisData) {
                    alert('No data to export');
                    return;
                }
                
                try {
                    const response = await fetch('/api/export', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            format: 'csv',
                            data: currentAnalysisData
                        })
                    });
                    
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'analysis.csv';
                    a.click();
                } catch (error) {
                    console.error('Export error:', error);
                }
            });

            document.getElementById('exportJSON')?.addEventListener('click', async () => {
                if (!currentAnalysisData) {
                    alert('No data to export');
                    return;
                }
                
                try {
                    const response = await fetch('/api/export', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            format: 'json',
                            data: currentAnalysisData
                        })
                    });
                    
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'analysis.json';
                    a.click();
                } catch (error) {
                    console.error('Export error:', error);
                }
            });

            // Load history
            async function loadHistory() {
                try {
                    const response = await fetch('/api/history');
                    const data = await response.json();
                    
                    const historyTable = document.getElementById('historyTable');
                    
                    if (data.records && data.records.length > 0) {
                        historyTable.innerHTML = \`
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">File</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Classification</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Confidence</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    \${data.records.map(record => \`
                                        <tr>
                                            <td class="px-6 py-4 text-sm text-gray-900">\${new Date(record.created_at).toLocaleString()}</td>
                                            <td class="px-6 py-4 text-sm text-gray-900">\${record.filename}</td>
                                            <td class="px-6 py-4 text-sm font-semibold text-blue-600">\${record.classification}</td>
                                            <td class="px-6 py-4 text-sm text-gray-900">\${(record.confidence * 100).toFixed(1)}%</td>
                                        </tr>
                                    \`).join('')}
                                </tbody>
                            </table>
                        \`;
                    } else {
                        historyTable.innerHTML = '<p class="text-gray-500">No analysis history available</p>';
                    }
                } catch (error) {
                    console.error('Error loading history:', error);
                    document.getElementById('historyTable').innerHTML = '<p class="text-red-500">Error loading history</p>';
                }
            }
        </script>
    </body>
    </html>
  `)
})

export default app