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

### Docker
```bash
docker build -t bank-api .
docker run -p 8000:8000 bank-api
```

The application will be available at `http://localhost:8000`

## API Endpoints

The application exposes various intentionally vulnerable endpoints for security testing and demonstration purposes.
