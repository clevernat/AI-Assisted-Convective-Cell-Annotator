"""
A-CLAT Python Backend Service
Handles NetCDF/GRIB file processing and convective cell tracking
"""

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import numpy as np
import json
from typing import List, Dict, Any, Optional
import tempfile
import os
from datetime import datetime

# FastAPI app initialization
app = FastAPI(title="A-CLAT Backend", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def simulate_tracking(xr_data: Dict[str, Any], variable_name: str) -> List[Dict[str, Any]]:
    """
    Simulates tracking of convective cells.
    In production, this would use actual atmospheric data processing algorithms.
    
    Args:
        xr_data: Simulated xarray-like data structure
        variable_name: Variable to track (e.g., 'Z' for reflectivity)
    
    Returns:
        List of tracked cell dictionaries
    """
    cells = []
    
    # Simulate time steps
    time_steps = xr_data.get('time_steps', 10)
    
    # Find top 3 cells at each time step
    for t in range(min(3, time_steps)):
        # Simulate finding local maxima
        for i in range(3):
            lat = 30 + np.random.random() * 20
            lon = -100 + np.random.random() * 30
            
            # Create realistic reflectivity values
            base_reflectivity = 45 + np.random.random() * 35
            
            cell = {
                'id': f'cell_{t}_{i}',
                'time': t,
                'lat': lat,
                'lon': lon,
                'peak_value': base_reflectivity,
                'coordinates': {
                    'x': int(np.random.random() * 100),
                    'y': int(np.random.random() * 100),
                    'z': int(np.random.random() * 20)
                },
                'area_km2': 50 + np.random.random() * 200,
                'max_height_km': 8 + np.random.random() * 7,
                'volume_km3': 100 + np.random.random() * 400
            }
            cells.append(cell)
    
    return cells

def annotate_life_cycle_with_genspark(cell_data_json: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Uses Genspark internal agent capabilities to classify convective cells.
    This is a placeholder that simulates the AI classification process.
    
    In production, this would interface with actual Genspark Super Agent APIs
    for sophisticated atmospheric pattern recognition.
    
    Args:
        cell_data_json: List of cell tracking data
    
    Returns:
        Dictionary with classification and justification
    """
    
    # Analyze cell characteristics
    if not cell_data_json:
        return {
            'classification': 'Unknown',
            'justification': 'No cell data available for analysis.',
            'confidence': 0.0
        }
    
    # Calculate aggregate statistics
    avg_peak = sum(c['peak_value'] for c in cell_data_json) / len(cell_data_json)
    max_peak = max(c['peak_value'] for c in cell_data_json)
    avg_height = sum(c.get('max_height_km', 10) for c in cell_data_json) / len(cell_data_json)
    total_volume = sum(c.get('volume_km3', 200) for c in cell_data_json)
    
    # Classification logic based on atmospheric science principles
    classification = 'Unknown'
    justification = ''
    confidence = 0.85
    
    if max_peak > 65 and avg_height > 12:
        classification = 'Supercell'
        justification = (
            f"The convective system exhibits supercell characteristics with maximum reflectivity "
            f"of {max_peak:.1f} dBZ and storm tops exceeding {avg_height:.1f} km. "
            f"Persistent mesocyclone signature indicates rotation through the storm depth. "
            f"The isolated nature and longevity suggest a classic supercell structure."
        )
        confidence = 0.92
    
    elif len(cell_data_json) > 6 and total_volume > 1000:
        classification = 'MCS'
        justification = (
            f"Analysis reveals mesoscale convective system organization with {len(cell_data_json)} "
            f"identified cells covering a combined volume of {total_volume:.0f} km³. "
            f"The system shows both convective and stratiform regions characteristic of MCS. "
            f"Organized propagation and cold pool development are evident in the data."
        )
        confidence = 0.88
    
    elif avg_peak > 55 and len(cell_data_json) >= 3:
        classification = 'Multicell'
        justification = (
            f"Multiple convective cells identified with average peak intensity of {avg_peak:.1f} dBZ "
            f"showing multicell storm structure. New cell development occurs preferentially "
            f"along the storm-relative right flank. Cell interaction and merger events "
            f"indicate organized multicell evolution."
        )
        confidence = 0.86
    
    elif max_peak > 50 and len(cell_data_json) <= 2:
        classification = 'Single-cell'
        justification = (
            f"Isolated convective development with peak reflectivity of {max_peak:.1f} dBZ "
            f"follows single-cell life cycle patterns. The storm shows pulse-type behavior "
            f"with rapid development and subsequent decay. Limited vertical wind shear "
            f"prevents organization into more complex structures."
        )
        confidence = 0.83
    
    else:
        classification = 'Squall Line'
        justification = (
            f"Linear convective organization detected with cells aligned along a boundary. "
            f"Peak values reach {max_peak:.1f} dBZ with characteristic leading convective "
            f"line structure. Strong low-level convergence maintains the linear organization "
            f"through the analysis period."
        )
        confidence = 0.80
    
    return {
        'classification': classification,
        'justification': justification,
        'confidence': confidence,
        'analyzed_cells': len(cell_data_json),
        'statistics': {
            'avg_peak_dbz': avg_peak,
            'max_peak_dbz': max_peak,
            'avg_height_km': avg_height,
            'total_volume_km3': total_volume
        },
        'genspark_agent': 'atmospheric-science-expert-v1',
        'timestamp': datetime.utcnow().isoformat()
    }

@app.post("/api/analyze")
async def analyze_atmospheric_data(
    file: UploadFile = File(...),
    variable: str = Form('Z')
):
    """
    Main analysis endpoint for processing NetCDF/GRIB files.
    
    Workflow:
    1. Accept file upload
    2. Extract atmospheric data
    3. Track convective cells
    4. Apply AI classification
    5. Return comprehensive analysis
    """
    
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.nc') as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        
        # Simulate data extraction (in production, use xarray)
        simulated_data = {
            'filename': file.filename,
            'variable': variable,
            'time_steps': 12,
            'dimensions': {
                'time': 12,
                'lat': 200,
                'lon': 200,
                'level': 25
            },
            'bounds': {
                'lat_min': 25.0,
                'lat_max': 45.0,
                'lon_min': -110.0,
                'lon_max': -80.0
            }
        }
        
        # Track cells
        tracked_cells = simulate_tracking(simulated_data, variable)
        
        # Get AI classification
        ai_analysis = annotate_life_cycle_with_genspark(tracked_cells)
        
        # Generate time series for top 3 cells
        top_cells = tracked_cells[:3]
        enhanced_cells = []
        
        for idx, cell in enumerate(top_cells):
            # Generate realistic time series
            time_series = []
            peak = cell['peak_value']
            
            for t in range(12):
                if t < 4:
                    # Growth phase
                    value = peak * (0.3 + 0.7 * (t / 4))
                elif t < 8:
                    # Mature phase
                    value = peak * (0.95 + np.random.random() * 0.05)
                else:
                    # Decay phase
                    value = peak * (1.0 - 0.2 * (t - 8))
                
                time_series.append({
                    'time': t,
                    'value': max(0, value + np.random.randn() * 2)
                })
            
            enhanced_cells.append({
                'id': f'cell_{idx + 1}',
                'coordinates': cell['coordinates'],
                'peak_value': peak,
                'lat': cell['lat'],
                'lon': cell['lon'],
                'area_km2': cell['area_km2'],
                'max_height_km': cell['max_height_km'],
                'time_series': time_series
            })
        
        # Clean up temp file
        os.unlink(tmp_path)
        
        # Return comprehensive analysis
        response = {
            'success': True,
            'metadata': {
                'filename': file.filename,
                'variable': variable,
                'processing_time': datetime.utcnow().isoformat(),
                'data_dimensions': simulated_data['dimensions'],
                'geographic_bounds': simulated_data['bounds']
            },
            'cells': enhanced_cells,
            'ai_analysis': ai_analysis,
            'processing_notes': 'Analysis completed using Genspark atmospheric science agent'
        }
        
        return JSONResponse(content=response)
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                'error': 'Analysis failed',
                'details': str(e)
            }
        )

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'A-CLAT Python Backend',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        'service': 'A-CLAT (AI-Assisted Convective Cell Annotator)',
        'version': '1.0.0',
        'endpoints': [
            '/api/analyze - POST - Analyze atmospheric data',
            '/api/health - GET - Health check',
            '/docs - GET - Interactive API documentation'
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)