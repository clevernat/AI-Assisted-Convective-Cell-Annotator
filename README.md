# A-CLAT (AI-Assisted Convective Cell Annotator)

## Project Overview
- **Name**: A-CLAT (AI-Assisted Convective Cell Annotator)
- **Goal**: Provide AI-powered analysis and classification of convective cells from atmospheric data
- **Features**: 
  - NetCDF/GRIB file upload and processing
  - Automatic tracking of convective cells
  - AI-powered storm classification (Supercell, Multicell, MCS, etc.)
  - Interactive visualizations with Plotly.js
  - Real-time intensity evolution tracking

## Architecture

### Frontend (Cloudflare Pages)
- **Framework**: Hono with TypeScript
- **UI**: TailwindCSS + Plotly.js for visualizations
- **Deployment**: Cloudflare Pages (edge runtime)

### Backend Options
1. **Simulated Processing** (Current Implementation)
   - Built into Hono app for demonstration
   - Simulates NetCDF processing and cell tracking
   - Uses Genspark agent simulation for classification

2. **Python Backend** (Optional Enhancement)
   - FastAPI service for actual NetCDF processing
   - Located in `python_backend/` directory
   - Can be deployed separately for production use

## URLs
- **Local Development**: http://localhost:3000
- **Live Demo**: https://3000-iiqzr0hiif3i299iwltsl-b32ec7bb.sandbox.novita.ai
- **Production**: Will be available after deployment to Cloudflare Pages
- **API Endpoints**:
  - `POST /api/analyze` - Main analysis endpoint
  - `GET /api/health` - Health check
  - `GET /` - Main web interface

## Data Architecture

### Data Models
- **Convective Cell**: 
  - ID, coordinates (x, y, z)
  - Peak reflectivity value (dBZ)
  - Time series data
  - Geographic location (lat/lon)
  - Physical properties (area, height, volume)

- **AI Classification**:
  - Storm type (Supercell, Multicell, MCS, Single-cell, Squall Line)
  - Confidence score
  - Justification text
  - Statistical analysis

### Storage Services
- **Current**: In-memory processing (suitable for edge deployment)
- **Future Enhancement**: Could integrate with Cloudflare D1 for historical data storage

### Data Flow
1. User uploads NetCDF/GRIB file
2. System extracts atmospheric data
3. Tracking algorithm identifies top 3 convective cells
4. Genspark AI agent classifies storm type
5. Results displayed with interactive visualizations

## User Guide

### How to Use A-CLAT

1. **Upload Data**
   - Click "Choose File" and select a NetCDF or GRIB file
   - Enter the variable name (default: "Z" for reflectivity)
   - Click "Analyze Convective Cells"

2. **View Results**
   - **AI Classification**: See the storm type and detailed justification
   - **Cell Analysis**: Review the top 3 tracked cells with their properties
   - **Visualization**: Interact with the intensity evolution chart

3. **Interpretation**
   - Higher dBZ values indicate stronger convection
   - Classification helps identify storm severity and potential hazards
   - Time series shows storm life cycle (growth, mature, decay phases)

## Features

### ✅ Currently Completed
- File upload interface for NetCDF/GRIB files
- Simulated cell tracking algorithm
- AI classification system (5 storm types)
- Interactive Plotly.js visualizations
- Responsive UI with TailwindCSS
- RESTful API endpoints
- Health check monitoring

### 📋 Features Not Yet Implemented
- Actual NetCDF/GRIB file parsing (currently simulated)
- Real-time data streaming
- Historical data persistence
- Multi-file batch processing
- Export functionality (CSV, JSON)
- Advanced visualization options (3D, animations)
- User authentication and session management

## Recommended Next Steps

1. **Production Deployment**
   - Deploy to Cloudflare Pages for global edge access
   - Configure custom domain if needed

2. **Enhanced Processing**
   - Integrate actual NetCDF parsing library
   - Implement real atmospheric tracking algorithms
   - Connect to real Genspark AI services

3. **Data Persistence**
   - Add Cloudflare D1 database for storing analysis results
   - Implement data export functionality

4. **Advanced Features**
   - Add support for radar data visualization
   - Implement ensemble forecasting
   - Create alert system for severe weather

## Deployment

### Local Development
```bash
# Install dependencies
npm install

# Build the project
npm run build

# Start development server
npm run dev:sandbox

# Or use PM2
pm2 start ecosystem.config.cjs
```

### Production Deployment
```bash
# Build for production
npm run build

# Deploy to Cloudflare Pages
npx wrangler pages deploy dist --project-name a-clat
```

### Python Backend (Optional)
```bash
cd python_backend
pip install -r requirements.txt
python app.py
```

## Technology Stack
- **Platform**: Cloudflare Pages
- **Backend**: Hono + TypeScript
- **Frontend**: HTML5 + TailwindCSS + Plotly.js
- **AI Integration**: Genspark Agent Ecosystem
- **Optional**: Python FastAPI for advanced processing

## Status
- **Platform**: Cloudflare Pages
- **Status**: ✅ Running Live
- **Demo URL**: https://3000-iiqzr0hiif3i299iwltsl-b32ec7bb.sandbox.novita.ai
- **Last Updated**: 2025-10-26
- **Backup**: Available at https://page.gensparksite.com/project_backups/a-clat-backup.tar.gz

## License
MIT License

## Contact
For questions or contributions, please contact the development team.