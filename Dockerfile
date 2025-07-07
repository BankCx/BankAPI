FROM python:3.13.4-alpine

USER root

EXPOSE 8000

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/main.py

EXPOSE 8000

CMD ["python", "main.py"] 