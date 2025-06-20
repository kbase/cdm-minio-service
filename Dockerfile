FROM python:3.13-slim

WORKDIR /app

# Install system dependencies and MinIO mc client
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install MinIO mc client
RUN wget https://dl.min.io/client/mc/release/linux-amd64/mc && \
    chmod +x mc && \
    mv mc /usr/local/bin/

# Install uv and Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install uv
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --inexact --no-dev

COPY src/ src/

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "--host", "0.0.0.0", "--port", "8000", "--factory", "src.main:create_application"]