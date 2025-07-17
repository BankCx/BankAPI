# Bank of Checkmarx - Bank API

This is the API for the intentionally vulnerable Bank of Checkmarx demo application built with Flask.

## Technology Stack
- **Framework**: Flask 2.0.1
- **Database**: SQLAlchemy with SQLite/PostgreSQL
- **Authentication**: JWT (intentionally vulnerable implementation)
- **CORS**: Flask-CORS

## Recommended Checkmarx One Configuration
- Criticality: 4
- Cloud Insights: Yes
- Internet-facing: Yes

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

The application exposes various intentionally vulnerable endpoints for security testing and demonstration purposes.
