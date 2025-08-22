# Bank of Checkmarx - Bank API

The Bank API is the primary REST API service for the Bank of Checkmarx demo application. It provides core banking functionality including user authentication, account management, file operations, and network utilities. This service is intentionally designed with security vulnerabilities for educational and demonstration purposes.

## Purpose & Overview

This API serves as the main entry point for banking operations and demonstrates various security vulnerabilities commonly found in web applications. It handles user authentication, account data retrieval, file processing, and system operations through a RESTful interface.

**Key Responsibilities:**
- User authentication and JWT token management
- Account balance and information retrieval
- File upload and processing operations
- Network diagnostic utilities (ping functionality)
- Comment and user-generated content handling
- Integration with core banking systems

## Technology Stack
- **Framework**: Flask 2.3.3
- **Database**: SQLAlchemy with SQLite/PostgreSQL support
- **Authentication**: JWT (intentionally vulnerable implementation)
- **CORS**: Flask-CORS for cross-origin resource sharing
- **HTTP Client**: Requests library for external API calls
- **Async Support**: aiohttp for asynchronous operations
- **Caching**: Redis integration
- **Cryptography**: Basic encryption utilities

## Features

### Authentication & Security
- JWT-based authentication system
- User login and session management
- API key authentication for sensitive endpoints
- CORS configuration for cross-origin requests

### Banking Operations
- Account balance retrieval
- Account information management
- Transaction processing integration
- User profile management

### File & Content Management
- File upload and processing
- Document handling and storage
- User comment submission
- Content validation and processing

### System Utilities
- Network ping functionality
- System health monitoring
- File system operations
- Process execution capabilities

## Running the Application

### Local Development
```bash
pip install -r requirements.txt
python main.py
```

### Docker Build and Run

#### Build the Docker Image
```bash
# Build the Docker image
docker build -t bank-api .

# Verify the image was created
docker images | grep bank-api
```

#### Run the Container
```bash
# Run the container in detached mode
docker run -d -p 8000:8000 --name bank-api-container bank-api

# Or run in foreground to see logs
docker run -p 8000:8000 --name bank-api-container bank-api
```

#### Container Management
```bash
# View running containers
docker ps

# View container logs
docker logs bank-api-container

# Stop the container
docker stop bank-api-container

# Remove the container
docker rm bank-api-container

# Remove the image
docker rmi bank-api
```

#### Troubleshooting

If you encounter build issues:
```bash
# Clean up Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -t bank-api .
```

If the container fails to start:
```bash
# Check container logs
docker logs bank-api-container

# Run container interactively for debugging
docker run -it --entrypoint /bin/bash bank-api
```

The application will be available at `http://localhost:8000`

## API Endpoints

The application exposes various intentionally vulnerable endpoints for security testing and demonstration purposes. Complete API documentation is available in the `swagger.yaml` file.

### Core Endpoints
- `POST /api/v1/login` - User authentication
- `GET /api/v1/accounts/{account_id}` - Account information retrieval
- `POST /api/v1/process-file` - File processing operations
- `POST /api/v1/ping` - Network diagnostic utility
- `POST /api/v1/comment` - User comment submission
- `POST /api/v1/upload` - File upload functionality

## Security Vulnerabilities

⚠️ **This is an intentionally vulnerable demo application.** Do not use in production.

This API contains deliberate security vulnerabilities for educational purposes:

### Authentication & Authorization
- Weak JWT implementation with hardcoded secrets
- Insufficient token validation
- Missing rate limiting on authentication endpoints
- Inadequate session management

### Input Validation
- Command injection vulnerabilities in ping and file processing
- SQL injection possibilities in database queries
- Insufficient input sanitization
- Missing file type validation

### System Security
- Unsafe subprocess execution
- File system access vulnerabilities
- Process execution without proper sandboxing
- Hardcoded credentials and secrets

### Network Security
- Unvalidated redirects
- SSRF (Server-Side Request Forgery) vulnerabilities
- Insecure network operations
- Missing network access controls

## Environment Configuration

Create a `.env` file for environment-specific settings:
```bash
# Database Configuration
DATABASE_URL=postgresql://admin:admin123@localhost:5432/bankapi
DATABASE_TYPE=postgresql

# Security Settings
JWT_SECRET_KEY=your-secret-key-here
API_SECRET=your-api-secret-here

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# Service URLs
CORE_BACKEND_URL=http://localhost:8080
FRAUD_DETECTION_URL=http://localhost:5000

# Logging
LOG_LEVEL=DEBUG
LOG_FILE=logs/bankapi.log
```

## Development

### Project Structure
```
BankAPI/
├── config/              # Configuration modules
├── middleware/          # Authentication and request middleware
├── models/             # Data models and database schemas
├── services/           # Business logic and service layer
├── scripts/            # Development and deployment scripts
├── logs/               # Application logs
├── main.py             # Application entry point
├── requirements.txt    # Python dependencies
├── requirements.in     # Unpinned dependencies for pip-tools
├── swagger.yaml        # API documentation
└── Dockerfile          # Container configuration
```

### Setup & Development
```bash
# Setup using provided scripts
./scripts/setup.sh      # Unix/Linux/macOS
scripts\setup.bat       # Windows

# Manual setup
python -m venv venv
source venv/bin/activate  # Unix/Linux/macOS
# or
venv\Scripts\activate     # Windows

pip install -r requirements.txt

# Start development server
./scripts/dev.sh         # Unix/Linux/macOS
python main.py           # Manual start
```

### Testing
```bash
# Run basic functionality test
python test_local.py

# Test API endpoints
curl -X POST http://localhost:8000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass"}'
```

## Integration

### Core Backend Integration
The Bank API integrates with the Core Backend service for:
- Account data synchronization
- Transaction processing
- User profile management
- Authentication validation

### Fraud Detection Integration
- Transaction risk assessment
- Suspicious activity reporting
- Real-time fraud alerts
- Behavioral analysis data sharing

### Wire Transfer Integration
- International transfer processing
- Compliance checking
- Transfer status updates
- Fee calculation

## Monitoring & Observability

### Logging
- Structured logging with configurable levels
- Request/response tracking
- Error logging and alerting
- Security event monitoring

### Health Checks
- Application health endpoint
- Database connectivity checks
- External service dependency monitoring
- Performance metrics collection

## Deployment

### Docker Deployment
```bash
# Build and run standalone
docker build -t bank-api .
docker run -p 8000:8000 bank-api

# Using Docker Compose (recommended)
docker-compose up bank-api
```

### Production Considerations
- Use proper secrets management
- Enable HTTPS/TLS encryption
- Configure rate limiting
- Set up monitoring and alerting
- Implement proper logging
- Use production-grade database
- Configure backup strategies

## Recommended Checkmarx One Configuration
- Criticality: 4
- Cloud Insights: Yes
- Internet-facing: Yes
