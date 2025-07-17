FROM python:3.11-slim

USER root

EXPOSE 8000

WORKDIR /app

# Install system dependencies needed for subprocess calls
RUN apt-get update && apt-get install -y \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/main.py

EXPOSE 8000

CMD ["python", "main.py"] 