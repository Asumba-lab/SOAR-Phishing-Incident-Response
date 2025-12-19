# SOAR Phishing Incident Response Platform

A comprehensive SOAR (Security Orchestration, Automation, and Response) solution built with FastAPI for automated phishing incident response. This platform provides a complete workflow for detecting, analyzing, and responding to phishing attempts through automated playbooks and a modern web interface.

## ✨ Features

- **RESTful API**: Built with FastAPI for high performance and automatic OpenAPI documentation
- **IOC Extraction**: Advanced extraction of Indicators of Compromise (IOCs) from email content
- **Threat Intelligence**: Integration with threat intelligence feeds for IOC enrichment
- **Risk Assessment**: Sophisticated risk scoring based on multiple threat factors
- **Automated Response**: Playbook-based incident response
- **Modern Web Interface**: Responsive React frontend with TypeScript
- **Containerized Deployment**: Docker support for easy deployment
- **CI/CD Pipeline**: GitHub Actions for automated testing and deployment

## 🏗️ Project Structure

```
soar-phishing/
├── docker/                 # Docker configuration
│   └── nginx/             # Nginx configuration
├── frontend/              # React frontend
│   ├── public/            # Static files
│   ├── src/               # React source code
│   └── Dockerfile         # Frontend Dockerfile
├── src/                   # Backend source code
│   ├── api/               # API routes and endpoints
│   ├── core/              # Core business logic
│   ├── db/                # Database models and migrations
│   └── ...                # Other backend components
├── .github/workflows/     # GitHub Actions workflows
├── docker-compose.yml     # Docker Compose configuration
└── Dockerfile             # Backend Dockerfile
```

## How It Works

1. **IOC Extraction**:
   - Extracts URLs, file hashes, and sender information from email content
   - Uses regex patterns to identify potential IOCs

2. **IOC Enrichment**:
   - Checks URLs against known malicious indicators
   - Verifies hashes against threat intelligence
   - Analyzes sender reputation

3. **Risk Scoring**:
   - Malicious URLs: +50 points
   - Blacklisted hashes: +30 points
   - Suspicious sender: +20 points
   - Risk thresholds:
     - ≥ 80: Critical - Automatic account isolation
     - 40-79: Medium - Requires analyst review
     - < 40: Low - Likely benign

4. **Response Actions**:
   - High-risk incidents trigger automatic account isolation
   - Medium-risk incidents are flagged for analyst review
   - Low-risk incidents are logged for monitoring

## 🚀 Quick Start with Docker

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Node.js 16+ (for frontend development)

### Running with Docker Compose

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/soar-phishing.git
   cd soar-phishing
   ```

2. Create and configure the environment file:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Start the application:
   ```bash
   docker-compose up --build
   ```

4. Access the application:
   - API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Frontend: http://localhost:3000

## 🛠️ Development

### Running Tests

```bash
# Backend tests
pytest

# Frontend tests
cd frontend
npm test
```

### Code Formatting

```bash
# Backend
black .
isort .
flake8
mypy .

# Frontend
cd frontend
npm run format
npm run lint
```

### Database Migrations

Create a new migration:
```bash
alembic revision --autogenerate -m "Your migration message"
```

Apply migrations:
```bash
alembic upgrade head
```

### Building for Production

```bash
# Build and start all services in production mode
docker-compose -f docker-compose.prod.yml up --build -d
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Database
POSTGRES_USER=soar
POSTGRES_PASSWORD=soar_password
POSTGRES_DB=soar_phishing

# Backend
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=postgresql://soar:soar_password@db:5432/soar_phishing

# Frontend
REACT_APP_API_URL=http://localhost:8000
```

### Running Locally (Development)

1. Start the backend services:
   ```bash
   docker-compose up -d db
   ```

2. Set up the backend:
   ```bash
   # Install dependencies
   poetry install

   # Run database migrations
   alembic upgrade head

   # Start the development server
   uvicorn src.main:app --reload
   ```

3. Start the frontend:
   ```bash
   cd frontend
   npm install
   npm start
   ```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Example Output

```
--- STEP 1: IOC EXTRACTION ---
{'urls': ['https://malicious-link.com'], 'hashes': ['5d41402abc4b2a76b9719d911017c592'], 'sender': 'attacker@malicious.com'}

--- STEP 2: ENRICHMENT ---
{'url_reputation': {'https://malicious-link.com': 'malicious'}, 'hash_reputation': {'5d41402abc4b2a76b9719d911017c592': 'blacklisted'}, 'sender_reputation': 'suspicious'}

--- STEP 3: RISK SCORE ---
Risk Score: 100

--- STEP 4: DECISION ---
[SIMULATION] Account victim@example.com DISABLED.
[SIMULATION] Password reset triggered.
[SIMULATION] MFA enforced.
```

## 🔒 Security

This project includes security features such as:
- JWT-based authentication
- Password hashing with bcrypt
- CORS protection
- Input validation with Pydantic
- Secure database session management

### Security Best Practices

For production deployment:
- Use HTTPS in production
- Set appropriate CORS policies
- Rotate secrets regularly
- Implement rate limiting
- Keep dependencies up to date
- Follow the principle of least privilege for database access
- Monitor and log security events

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Database powered by [SQLAlchemy](https://www.sqlalchemy.org/) and [Alembic](https://alembic.sqlalchemy.org/)
- Frontend built with [React](https://reactjs.org/) (in development)
