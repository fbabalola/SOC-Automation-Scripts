# SOC Automation Scripts - Docker Image
# Multi-stage build for smaller image size

FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Production image
FROM python:3.11-slim

LABEL maintainer="Firebami Babalola <firebamibabalola@gmail.com>"
LABEL description="SOC Automation Scripts - IOC extraction, email analysis, log parsing"
LABEL version="1.0.0"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash analyst

# Copy installed packages from builder
COPY --from=builder /root/.local /home/analyst/.local

# Copy application code
COPY tools/ ./tools/
COPY lib/ ./lib/

# Set up environment
ENV PATH=/home/analyst/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER analyst

# Create entrypoint script
RUN echo '#!/bin/bash\n\
if [ "$1" = "ioc_extractor" ]; then\n\
    shift\n\
    python /app/tools/ioc_extractor.py "$@"\n\
elif [ "$1" = "email_analyzer" ]; then\n\
    shift\n\
    python /app/tools/email_analyzer.py "$@"\n\
elif [ "$1" = "log_parser" ]; then\n\
    shift\n\
    python /app/tools/log_parser.py "$@"\n\
else\n\
    echo "Usage: docker run soc-tools <tool> [options]"\n\
    echo "Tools: ioc_extractor, email_analyzer, log_parser"\n\
fi' > /home/analyst/entrypoint.sh \
    && chmod +x /home/analyst/entrypoint.sh

ENTRYPOINT ["/home/analyst/entrypoint.sh"]
CMD ["--help"]
