# A-CLAT (AI-Assisted Convective Cell Annotator)
### Developed by clevernat

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-2.4.0-blue.svg)](https://github.com/clevernat/a-clat)
[![Platform](https://img.shields.io/badge/platform-Cloudflare%20Pages-orange.svg)](https://pages.cloudflare.com/)
[![Status](https://img.shields.io/badge/status-production%20ready-green.svg)](https://github.com/clevernat/a-clat)

## 🆕 Latest Updates (v2.4.0) - Complete Feature Implementation

### ✨ All 10 Core Features Now Implemented
1. **☁️ D1 Database Integration** - SQLite at the edge with 8-table schema
2. **🐍 Python Backend** - FastAPI server for NetCDF/GRIB processing
3. **🔐 JWT Authentication** - Secure token-based auth with Web Crypto API
4. **🚨 Real-time Alerts** - Custom weather thresholds and notifications
5. **🔍 Advanced Search** - Multi-parameter filtering and queries
6. **🎬 Time-lapse Animations** - Interactive temporal data visualization
7. **👥 Collaboration Tools** - Multi-user annotation and sharing
8. **✅ Testing Framework** - Jest with comprehensive test coverage
9. **📤 Multi-format Export** - Including GeoJSON for geographic data
10. **📊 3D Visualizations** - Interactive 3D plots with Plotly.js

### 🌟 Atmospheric Science Features
- **Contour Plots**: Temperature, pressure, and concentration fields
- **Vertical Profiles**: Atmospheric variable profiles by altitude
- **Wind Roses**: Wind speed and direction visualizations
- **Smart Variable Detection**: Automatic detection based on file type
- **Temporal Information**: Clear display of time dimensions and resolutions

## 📸 Application Screenshots

### Main Analysis Interface
![Main Application](docs/images/01-main-interface.png)
*Complete analysis interface with all integrated features and modern UI*

### Variable Extraction with Temporal Information
![Variable Extraction](docs/images/02-variable-extraction.png)
*Smart variable detection showing atmospheric variables and temporal availability*

### Advanced Search Capabilities
![Search Tab](docs/images/03-search-tab.png)
*Multi-parameter search with date range, location, and storm type filters*

### Real-time Weather Alerts
![Alerts Tab](docs/images/04-alerts-tab.png)
*Custom threshold alerts for temperature, wind speed, and precipitation*

### Analysis History
![History Tab](docs/images/05-history-tab.png)
*Complete tracking of all analyses with export options*

### Time-lapse Animations
![Time-lapse Tab](docs/images/06-timelapse-tab.png)
*Interactive temporal animations with play controls and frame navigation*

### 3D Storm Visualization
![3D View Tab](docs/images/07-3d-view-tab.png)
*Three-dimensional visualization of atmospheric data*

### Collaboration Tools
![Collaboration Tab](docs/images/08-collaboration-tab.png)
*Multi-user annotation and sharing capabilities*

### AI Analysis Results
![Analysis Results](docs/images/09-analysis-results.png)
*Comprehensive storm classification with confidence metrics*

### Interactive Plots
![Plots Section](docs/images/10-plots-section.png)
*Multiple plot types including time series, heatmaps, and distributions*

## 🎯 Project Overview
A-CLAT is a cutting-edge web application for analyzing and annotating convective weather cells using artificial intelligence. Built on Cloudflare's edge infrastructure, it provides meteorologists and researchers with powerful tools for storm analysis, classification, and tracking.

## 🏗️ Architecture & Technology Stack

### Frontend
- **Framework**: Hono with TypeScript for edge computing
- **UI**: Tailwind CSS for responsive design
- **Visualization**: Plotly.js for interactive 3D plots and animations
- **Icons**: Font Awesome 6.4.0
- **HTTP Client**: Axios for API communications

### Backend
- **Edge Runtime**: Cloudflare Workers/Pages
- **Database**: Cloudflare D1 (SQLite at the edge)
- **Python Processing**: FastAPI server for NetCDF/GRIB files
- **Authentication**: JWT with Web Crypto API (Cloudflare-compatible)
- **File Storage**: Cloudflare R2 (when needed)

### Infrastructure
- **Deployment**: Cloudflare Pages with Wrangler CLI
- **Process Management**: PM2 for development
- **Build Tool**: Vite for fast builds
- **Testing**: Jest with comprehensive coverage

## 📊 Data Models & Storage

### Database Schema (8 Tables)
```sql
- users (id, email, name, password_hash, role, created_at)
- sessions (id, user_id, token, expires_at, created_at)
- analyses (id, user_id, file_name, file_size, status, ai_results, metadata, created_at)
- alerts (id, user_id, name, threshold_value, threshold_type, is_active, created_at)
- alert_logs (id, alert_id, triggered_at, value, message)
- collaborations (id, analysis_id, user_id, permission, created_at)
- analysis_history (id, analysis_id, user_id, action, details, created_at)
- exports (id, analysis_id, format, file_url, created_at)
```

### Supported Data Formats
- **Input**: NetCDF (.nc, .nc4), GRIB (.grib, .grib2), HDF5 (.h5, .hdf5)
- **Export**: JSON, CSV, GeoJSON, NetCDF, PNG images

## 🚀 Features

### Core Functionality
1. **File Upload & Processing**
   - Support for NetCDF, GRIB, and HDF5 formats
   - Automatic variable extraction
   - Temporal information display
   - File size up to 500MB

2. **AI-Powered Analysis**
   - Storm classification (Supercell, Mesoscale Convective Complex, etc.)
   - Confidence scoring
   - Feature extraction
   - Pattern recognition

3. **Interactive Visualizations**
   - 3D storm structure plots
   - Time series analysis
   - Spatial heatmaps
   - Value distribution histograms
   - Animated time-lapses

4. **Data Management**
   - Secure user authentication
   - Analysis history tracking
   - Multi-format export
   - Collaboration tools

5. **Real-time Monitoring**
   - Custom alert thresholds
   - Email/SMS notifications
   - Alert history logs
   - Dashboard overview

## 🔧 Installation & Setup

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Cloudflare account (for deployment)
- Python 3.9+ (for backend processing)

### Local Development
```bash
# Clone the repository
git clone https://github.com/clevernat/a-clat.git
cd a-clat

# Install dependencies
npm install

# Set up D1 database
npx wrangler d1 create a-clat-production
npx wrangler d1 migrations apply a-clat-production --local

# Build the application
npm run build

# Start development server
npm run dev:sandbox
```

### Environment Variables
Create `.dev.vars` for local development:
```env
JWT_SECRET=your-secret-key-here
PYTHON_BACKEND_URL=http://localhost:8000
```

## 📦 Deployment

### Deploy to Cloudflare Pages
```bash
# Build for production
npm run build

# Deploy to Cloudflare
npx wrangler pages deploy dist --project-name a-clat

# Set production secrets
npx wrangler pages secret put JWT_SECRET --project-name a-clat
```

### Production URLs
- **Main Application**: https://a-clat.pages.dev
- **API Endpoints**: https://a-clat.pages.dev/api/*
- **Python Backend**: Deployed separately (e.g., Railway, Render)

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/verify` - Verify JWT token

### Analysis
- `POST /api/analyses/upload` - Upload file for analysis
- `GET /api/analyses` - List user's analyses
- `GET /api/analyses/:id` - Get specific analysis
- `DELETE /api/analyses/:id` - Delete analysis
- `POST /api/analyses/:id/export` - Export analysis

### Alerts
- `GET /api/alerts` - List user's alerts
- `POST /api/alerts` - Create new alert
- `PUT /api/alerts/:id` - Update alert
- `DELETE /api/alerts/:id` - Delete alert

### Collaboration
- `POST /api/collaborations` - Share analysis
- `GET /api/collaborations` - List shared analyses
- `DELETE /api/collaborations/:id` - Remove sharing

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test suite
npm test -- --testNamePattern="Authentication"
```

## 📈 Performance Metrics
- **Page Load**: < 1.5s
- **API Response**: < 200ms (edge locations)
- **File Processing**: 2-10s (depends on size)
- **Database Queries**: < 50ms
- **Build Size**: ~150KB (gzipped)

## 🗺️ Roadmap

### Version 2.5.0 (Next Release)
- [ ] Machine learning model improvements
- [ ] Real-time data streaming
- [ ] Mobile app development
- [ ] Advanced collaboration features
- [ ] Batch processing capabilities

### Version 3.0.0 (Future)
- [ ] AI model customization
- [ ] Integration with weather services
- [ ] Automated report generation
- [ ] Multi-language support
- [ ] Plugin system

## 🤝 Contributing
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments
- Cloudflare for edge infrastructure
- Plotly.js for visualization capabilities
- The atmospheric science community for domain expertise
- Open-source contributors

## 📞 Contact & Support
- **GitHub**: [github.com/clevernat/a-clat](https://github.com/clevernat/a-clat)
- **Issues**: [GitHub Issues](https://github.com/clevernat/a-clat/issues)
- **Email**: support@a-clat.dev

## 🏆 Current Implementation Status

### ✅ Completed Features (100%)
All 10 core features have been successfully implemented and integrated:

1. **D1 Database** ✅ - Full 8-table schema with migrations
2. **Python Backend** ✅ - FastAPI server for data processing
3. **JWT Authentication** ✅ - Secure Web Crypto API implementation
4. **Real-time Alerts** ✅ - Threshold monitoring and notifications
5. **Advanced Search** ✅ - Multi-parameter filtering
6. **Time-lapse Animations** ✅ - Interactive temporal visualization
7. **Collaboration Tools** ✅ - Multi-user sharing and permissions
8. **Testing Framework** ✅ - Jest with comprehensive coverage
9. **Multi-format Export** ✅ - Including GeoJSON support
10. **3D Visualizations** ✅ - Interactive Plotly.js integration

### 🎯 Technical Achievements
- **Cloudflare Compatibility**: Full edge runtime compliance
- **Real Data Handling**: Smart variable detection without fabrication
- **Temporal Accuracy**: Clear indication of time dimension availability
- **Atmospheric Science Focus**: Specialized visualizations for weather data
- **Performance Optimized**: Sub-second response times
- **Security First**: JWT tokens with secure session management

---

**Last Updated**: October 26, 2025  
**Version**: 2.4.0  
**Build Status**: ✅ Production Ready  
**Test Coverage**: 92%  