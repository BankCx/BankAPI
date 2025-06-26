# Updated to use a more recent base image
FROM python:3.13.4-alpine

# Intentionally vulnerable - running as root
USER root

# Intentionally vulnerable - no healthcheck
# Intentionally vulnerable - no non-root user
# Intentionally vulnerable - no security scanning

WORKDIR /app

# Intentionally vulnerable - copying requirements first (bad layer caching)
COPY requirements.txt .

# Intentionally vulnerable - no package integrity check
RUN pip install --no-cache-dir -r requirements.txt

# Intentionally vulnerable - copying all files
COPY . .

# Intentionally vulnerable - no build optimization
# Intentionally vulnerable - no security scanning
# Intentionally vulnerable - no resource limits

# Intentionally vulnerable - exposing all ports
EXPOSE 8000

# Intentionally vulnerable - running as root
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# Intentionally vulnerable - no healthcheck
# Intentionally vulnerable - no security context
# Intentionally vulnerable - no read-only filesystem 