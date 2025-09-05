# IOC Analyzer

A comprehensive web application for analyzing Indicators of Compromise (IOCs) with a retro terminal aesthetic. This tool allows security professionals to analyze various types of IOCs including IP addresses, domains, URLs, file hashes, and email addresses using multiple threat intelligence sources.

## Features

### Core Functionality
- **Single IOC Analysis**: Analyze individual indicators with detailed results
- **Bulk IOC Analysis**: Process multiple IOCs simultaneously from file upload or text input
- **Multi-Source Intelligence**: Integration with multiple threat intelligence APIs
- **Real-time Results**: Live analysis with progress tracking
- **Export Capabilities**: Download results in various formats

### Supported IOC Types
- IP Addresses (IPv4/IPv6)
- Domain Names
- URLs
- File Hashes (MD5, SHA1, SHA256)
- Email Addresses

### Integrated Threat Intelligence Sources
- **VirusTotal**: File and URL analysis, IP/domain reputation
- **AbuseIPDB**: IP address reputation and abuse reports
- **AlienVault OTX**: Open Threat Exchange intelligence
- **Shodan**: Internet-connected device information
- **WHOIS**: Domain registration information

## Technology Stack

### Frontend
- **React 18**: Modern React with hooks and functional components
- **Vite**: Fast build tool and development server
- **Tailwind CSS**: Utility-first CSS framework with custom retro theme
- **Custom Components**: Modular component architecture

### Backend
- **FastAPI**: High-performance Python web framework
- **SQLite**: Local caching database
- **Uvicorn**: ASGI server for production deployment
- **Python 3.13**: Latest Python features and performance

## Installation

### Prerequisites
- Node.js 18+ and npm
- Python 3.13+
- Git

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. Start the backend server:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open your browser to `http://localhost:3000`

## Configuration

### API Keys
Create a `.env` file in the backend directory with your API keys:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
SHODAN_API_KEY=your_shodan_api_key
```

### Obtaining API Keys
- **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/)
- **AbuseIPDB**: Register at [abuseipdb.com](https://www.abuseipdb.com/)
- **AlienVault OTX**: Register at [otx.alienvault.com](https://otx.alienvault.com/)
- **Shodan**: Register at [shodan.io](https://www.shodan.io/)

## Usage

### Single IOC Analysis
1. Navigate to the main page
2. Enter an IOC in the input field
3. Click "Analyze" to start the analysis
4. View results in organized tabs by source
5. Click on external tool links for additional analysis

### Bulk IOC Analysis
1. Click on "Bulk Analysis" tab
2. Either:
   - Upload a text file with IOCs (one per line)
   - Paste IOCs directly into the text area
3. Click "Analyze All" to start bulk processing
4. Monitor progress and view results in the table
5. Click on individual rows to expand detailed results

### Exporting Results
- Individual results can be copied or saved
- Bulk results can be exported to CSV or JSON formats
- Use browser print functionality for PDF export

## API Documentation

The backend provides a RESTful API with the following endpoints:

- `POST /analyze` - Analyze a single IOC
- `POST /bulk-analyze` - Analyze multiple IOCs
- `GET /health` - Health check endpoint
- `GET /docs` - Interactive API documentation (Swagger UI)

Visit `http://localhost:8000/docs` for interactive API documentation.

## Development

### Project Structure
```
ioc-analyzer-full/
├── backend/
│   ├── main.py          # FastAPI application
│   ├── apis.py          # API integration logic
│   ├── cache.py         # Caching functionality
│   └── requirements.txt # Python dependencies
└── frontend/
    ├── src/
    │   ├── components/   # React components
    │   ├── contexts/     # React contexts
    │   └── styles/       # CSS and styling
    ├── package.json     # Node.js dependencies
    └── tailwind.config.js # Tailwind configuration
```

### Custom Styling
The application uses a custom retro theme with:
- Terminal green colors (`#00ff00`, `#33ff33`)
- Dark backgrounds (`#1a1a1a`, `#2d2d2d`)
- Square borders with retro shadows
- Monospace fonts for terminal feel

### Adding New IOC Types
1. Update the backend `apis.py` to handle the new IOC type
2. Add validation logic for the new format
3. Update frontend components to display results
4. Add appropriate styling and icons

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -m 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## Security Considerations

- API keys are stored securely in environment variables
- No sensitive data is logged or cached permanently
- All external API calls are made server-side
- Input validation prevents injection attacks
- CORS is properly configured for security
