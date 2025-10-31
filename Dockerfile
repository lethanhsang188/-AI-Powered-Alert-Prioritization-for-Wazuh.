FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY bin/ ./bin/
COPY app.py .

# Create state directory
RUN mkdir -p /app/state

# Make scripts executable
RUN chmod +x bin/*.py

# Expose API port
EXPOSE 8088

# Default command (can be overridden in docker-compose)
CMD ["python", "app.py"]

