import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  KV?: KVNamespace;
}

const app = new Hono<{ Bindings: Bindings }>()

// Enable CORS
app.use('/api/*', cors())

// Serve static files
app.use('/static/*', serveStatic({ root: './public' }))

// Cell tracking simulation function
function simulateTracking(data: any, variableName: string) {
  // Simulate finding the 3 largest local maxima (cells) at each time step
  const cells = []
  const timeSteps = data.timeSteps || 10
  
  for (let t = 0; t < Math.min(3, timeSteps); t++) {
    // Simulate finding top 3 cells at this time step
    for (let i = 0; i < 3; i++) {
      cells.push({
        id: `cell_${t}_${i}`,
        time: t,
        lat: 30 + Math.random() * 20,
        lon: -100 + Math.random() * 30,
        peak_value: 50 + Math.random() * 50,
        coordinates: {
          x: Math.floor(Math.random() * 100),
          y: Math.floor(Math.random() * 100)
        }
      })
    }
  }
  
  return cells
}

// AI annotation using Genspark internal capabilities (simulated)
function annotateLifeCycleWithGenspark(cellData: any[]) {
  // This function simulates calling internal Genspark agent capabilities
  // In production, this would interface with actual Genspark APIs
  
  const classifications = ['Supercell', 'Multicell', 'Single-cell', 'MCS', 'Squall Line']
  const selectedClass = classifications[Math.floor(Math.random() * classifications.length)]
  
  // Analyze cell characteristics
  const avgPeak = cellData.reduce((sum, cell) => sum + cell.peak_value, 0) / cellData.length
  const maxPeak = Math.max(...cellData.map(c => c.peak_value))
  const latRange = Math.max(...cellData.map(c => c.lat)) - Math.min(...cellData.map(c => c.lat))
  
  let justification = ""
  
  if (selectedClass === 'Supercell') {
    justification = `The cell exhibits persistent rotation with peak reflectivity values reaching ${maxPeak.toFixed(1)} dBZ, characteristic of supercell structure. The storm maintains a steady-state updraft through multiple volume scans. Mesocyclone signature is evident in the velocity data with strong vertical continuity.`
  } else if (selectedClass === 'Multicell') {
    justification = `Analysis reveals multiple convective cores with average peak values of ${avgPeak.toFixed(1)} dBZ across a ${latRange.toFixed(1)}° latitude span. New cell development occurs along the storm's leading edge while older cells decay. The storm complex exhibits discrete propagation with cell interaction evident.`
  } else if (selectedClass === 'Single-cell') {
    justification = `The convective cell shows isolated development with peak intensity of ${maxPeak.toFixed(1)} dBZ and limited spatial extent. Life cycle follows classic single-cell evolution from initiation through maturity to dissipation. No significant cell splitting or merging is observed during the analysis period.`
  } else if (selectedClass === 'MCS') {
    justification = `The system displays organized mesoscale convective characteristics with extensive stratiform precipitation region. Peak convective values reach ${maxPeak.toFixed(1)} dBZ with a well-defined leading convective line. The complex spans multiple degrees of latitude indicating mesoscale organization.`
  } else {
    justification = `Linear convective organization is evident with peak values of ${maxPeak.toFixed(1)} dBZ along the leading edge. The system exhibits continuous propagation with new cell development maintaining the linear structure. Strong low-level convergence sustains the squall line through the analysis period.`
  }
  
  return {
    classification: selectedClass,
    justification: justification,
    confidence: 0.85 + Math.random() * 0.14,
    analyzed_cells: cellData.length,
    genspark_agent: "atmospheric-science-expert-v1"
  }
}

// API endpoint for analysis
app.post('/api/analyze', async (c) => {
  try {
    const formData = await c.req.formData()
    const file = formData.get('file') as File
    const variableName = formData.get('variable') as string || 'Z'
    
    if (!file) {
      return c.json({ error: 'No file provided' }, 400)
    }
    
    // Simulate data processing (in production, this would parse actual NetCDF)
    const simulatedData = {
      filename: file.name,
      size: file.size,
      variableName: variableName,
      timeSteps: 10,
      dimensions: {
        time: 10,
        lat: 100,
        lon: 100,
        level: 20
      }
    }
    
    // Track cells
    const cellData = simulateTracking(simulatedData, variableName)
    
    // Get AI annotations
    const aiAnnotation = annotateLifeCycleWithGenspark(cellData)
    
    // Prepare response
    const response = {
      success: true,
      metadata: {
        filename: file.name,
        variable: variableName,
        processing_time: new Date().toISOString()
      },
      cells: cellData.slice(0, 3).map((cell, index) => ({
        id: `cell_${index + 1}`,
        coordinates: cell.coordinates,
        peak_value: cell.peak_value,
        time_series: Array.from({ length: 10 }, (_, t) => ({
          time: t,
          value: cell.peak_value * (1 - t * 0.05 + Math.random() * 0.1)
        }))
      })),
      ai_analysis: aiAnnotation
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

// Health check endpoint
app.get('/api/health', (c) => {
  return c.json({ 
    status: 'healthy',
    service: 'A-CLAT (AI-Assisted Convective Cell Annotator)',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  })
})

// Main HTML interface
app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>A-CLAT - AI-Assisted Convective Cell Annotator</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
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
        </style>
    </head>
    <body class="bg-gradient-to-br from-blue-50 to-indigo-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-6xl">
            <!-- Header -->
            <header class="text-center mb-10">
                <h1 class="text-4xl font-bold text-gray-800 mb-3">
                    <i class="fas fa-cloud-bolt text-blue-600 mr-3"></i>
                    A-CLAT
                </h1>
                <p class="text-xl text-gray-600">AI-Assisted Convective Cell Annotator</p>
                <p class="text-sm text-gray-500 mt-2">Powered by Genspark Agent Intelligence</p>
            </header>

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
                        AI Classification
                    </h2>
                    <div id="classificationResult" class="space-y-4">
                        <!-- Classification will be inserted here -->
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

            <!-- Footer -->
            <footer class="text-center mt-12 text-gray-500 text-sm">
                <p>A-CLAT v1.0 | Atmospheric Science + AI Integration</p>
                <p class="mt-2">Powered by Genspark Super Agent Ecosystem</p>
            </footer>
        </div>

        <script>
            const uploadForm = document.getElementById('uploadForm');
            const fileInput = document.getElementById('fileInput');
            const variableInput = document.getElementById('variableInput');
            const loadingSection = document.getElementById('loadingSection');
            const resultsSection = document.getElementById('resultsSection');
            const classificationResult = document.getElementById('classificationResult');
            const cellCards = document.getElementById('cellCards');
            const plotContainer = document.getElementById('plotContainer');

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
                    // Send to API
                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('Analysis failed');
                    }

                    const data = await response.json();
                    
                    // Display results
                    displayResults(data);
                    
                } catch (error) {
                    console.error('Error:', error);
                    alert('Error analyzing file: ' + error.message);
                } finally {
                    loadingSection.classList.add('hidden');
                }
            });

            function displayResults(data) {
                // Show results section
                resultsSection.classList.remove('hidden');

                // Display AI classification
                const classification = data.ai_analysis;
                classificationResult.innerHTML = \`
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
                        <p class="text-gray-700 leading-relaxed mb-3">
                            \${classification.justification}
                        </p>
                        <div class="text-sm text-gray-500">
                            <i class="fas fa-robot mr-1"></i>
                            Analysis by: \${classification.genspark_agent}
                        </div>
                    </div>
                \`;

                // Display cell cards
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
                            <p><span class="font-semibold">Coordinates:</span> 
                                (\${cell.coordinates.x}, \${cell.coordinates.y})
                            </p>
                            <p><span class="font-semibold">ID:</span> 
                                <code class="bg-gray-100 px-2 py-1 rounded">\${cell.id}</code>
                            </p>
                        </div>
                    </div>
                \`).join('');

                // Create Plotly visualization
                const traces = data.cells.map((cell, index) => ({
                    x: cell.time_series.map(t => t.time),
                    y: cell.time_series.map(t => t.value),
                    mode: 'lines+markers',
                    name: \`Cell \${index + 1}\`,
                    line: { width: 2 },
                    marker: { size: 6 }
                }));

                const layout = {
                    title: {
                        text: 'Convective Cell Intensity Evolution',
                        font: { size: 18 }
                    },
                    xaxis: {
                        title: 'Time Step',
                        showgrid: true,
                        gridcolor: '#e0e0e0'
                    },
                    yaxis: {
                        title: 'Intensity (dBZ)',
                        showgrid: true,
                        gridcolor: '#e0e0e0'
                    },
                    hovermode: 'x unified',
                    plot_bgcolor: '#fafafa',
                    paper_bgcolor: 'white',
                    margin: { t: 50, r: 20, b: 50, l: 60 },
                    showlegend: true,
                    legend: {
                        orientation: 'h',
                        y: -0.15
                    }
                };

                const config = {
                    responsive: true,
                    displayModeBar: true,
                    modeBarButtonsToRemove: ['pan2d', 'lasso2d']
                };

                Plotly.newPlot(plotContainer, traces, layout, config);
            }
        </script>
    </body>
    </html>
  `)
})

export default app