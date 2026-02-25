# ATLAS - Advanced Traffic Layer Anomaly System

An enterprise-grade Cloud-Native Security Operations Center (SOC) platform for proactive defense and anomaly detection.

## 🚀 What ATLAS Does

ATLAS transforms raw system logs into actionable intelligence, using machine learning to detect abnormal behavior and prevent financial loss and security breaches without disrupting normal business operations.

### Core Capabilities

- **Financial Protection**: Detects API abuse and infinite loops that could cost thousands in third-party API fees
- **Security Threat Detection**: Identifies brute-force attacks, network scanning, and data exfiltration attempts  
- **Smart Containment**: Progressive response system (Alert → Soft Limit → Hard Block) to avoid false positives
- **AI-Powered Analysis**: Local AI assistant generates human-readable threat summaries and suggests remediation
- **Comprehensive Visibility**: Centralized dashboard for APIs, databases, network traffic, and endpoint security

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   Data Layer    │
│   (Next.js)     │◄──►│   (FastAPI)     │◄──►│  (Elasticsearch)│
│   Port: 3000    │    │   Port: 8000    │    │   Port: 9200    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  ML & AI Layer   │
                       │ (Scikit-learn)  │
                       │   (Ollama)      │
                       └─────────────────┘
```

## 🛠️ Tech Stack

### Backend
- **FastAPI**: High-performance async web framework
- **Elasticsearch**: Log aggregation and search
- **Redis**: Caching and session management
- **Scikit-learn**: Machine learning for anomaly detection
- **Ollama**: Local LLM for AI analysis
- **Wazuh**: Endpoint security integration

### Frontend
- **Next.js 15**: React framework with App Router
- **TypeScript**: Type-safe development
- **TailwindCSS**: Modern styling
- **Radix UI**: Accessible components
- **Recharts**: Data visualization
- **Genkit**: AI integration

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/mohankrishnan13/Atlas-back-end.git
git clone https://github.com/mohankrishnan13/atlas-fron-end.git
```

### 2. Environment Configuration

#### Backend Environment
Create `atlas-backend/.env`:
```bash
# ATLAS - Advanced Traffic Layer Anomaly System
APP_NAME=ATLAS
APP_ENV=development
DEBUG=true

# Elasticsearch
ELASTIC_HOST=http://localhost:9201
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=changeme

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Ollama LLM
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Wazuh
WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=wazuh
WAZUH_PASSWORD=wazuh_password
```

#### Frontend Environment
Create `atlas-fron-end/.env`:
```bash
# Backend API URL
ATLAS_BACKEND_URL=http://localhost:8000

# Next.js
NODE_ENV=development

# AI Configuration (optional)
GEMINI_API_KEY=your_gemini_api_key_here
```

### 3. Start with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 4. Access the Application

- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Elasticsearch**: http://localhost:9201
- **Health Check**: http://localhost:8000/health

## 📊 Dashboard Features

### Overview Page
- Real-time API request metrics
- Error rate monitoring
- Active alerts counter
- Cost risk assessment
- Microservices health topology
- System-wide anomaly detection

### API Monitoring
- API usage analytics
- Cost tracking per endpoint
- Performance metrics
- Request routing visualization

### Network Traffic
- Bandwidth utilization
- Connection monitoring
- Network anomaly detection
- Security event tracking

### Endpoint Security
- Wazuh integration
- OS distribution analytics
- Malware alert monitoring
- Employee workstation status

### Database Monitoring
- Query performance analysis
- Connection pool monitoring
- Suspicious activity detection
- Data export tracking

### Incident Management
- Security incident timeline
- Threat severity classification
- Automated containment actions
- AI-powered incident analysis

## 🔧 Development Setup

### Backend Development
```bash
cd atlas-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development
```bash
cd atlas-fron-end

# Install dependencies
npm install

# Start development server
npm run dev
```

## 🔍 API Endpoints

### Dashboard Endpoints
- `GET /api/v1/dashboard/overview` - Main dashboard data
- `GET /api/v1/dashboard/api-monitoring` - API usage metrics
- `GET /api/v1/dashboard/network-traffic` - Network analytics
- `GET /api/v1/dashboard/endpoint-security` - Wazuh security data
- `GET /api/v1/dashboard/db-monitoring` - Database metrics
- `GET /api/v1/dashboard/incidents` - Security incidents

### System Endpoints
- `GET /` - Service information
- `GET /health` - Health check
- `GET /docs` - API documentation

## 🤖 AI Integration

ATLAS includes a local AI assistant that:
- Analyzes security incidents automatically
- Generates human-readable threat summaries
- Suggests 1-click remediation actions
- Provides daily threat briefings

## 🔒 Security Features

- **Progressive Containment**: Multi-tier response system
- **ML-Based Anomaly Detection**: Isolation Forest algorithm
- **Real-time Monitoring**: Sub-second threat detection
- **Zero False Positive Policy**: Context-aware blocking
- **Compliance Ready**: Audit logging and reporting

## 📈 Monitoring & Observability

- **Elasticsearch**: Centralized log storage
- **Redis**: Real-time caching and sessions
- **Health Checks**: Container orchestration ready
- **Structured Logging**: JSON-formatted logs
- **Performance Metrics**: Request latency tracking

## 🚀 Deployment

### Production Deployment
```bash
# Build and deploy
docker-compose -f docker-compose.prod.yml up -d

# Scale services
docker-compose up -d --scale atlas-backend=3
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation at `/docs`
- Review the health check endpoint at `/health`

---

**ATLAS** - Your intelligent security operations center for the cloud-native era.
