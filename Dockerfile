# Builder stage
FROM python:3.9-slim-bullseye AS builder

# Create working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application contents
COPY service/ ./service/

# Create a non-root user and change ownership
RUN useradd --uid 1000 cbotee && chown -R cbotee /app

# Final image stage
FROM python:3.9-slim-bullseye

# Create working directory
WORKDIR /app

# Install dependencies in final stage
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy only the necessary artifacts from builder stage
COPY --from=builder /app /app

# Create a non-root user and change ownership in final stage
RUN useradd --uid 1000 cbotee && chown -R cbotee /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Switch to non-root user
USER cbotee

# Expose service port
EXPOSE 5000

# Use gunicorn with a process manager (better for production)
CMD ["gunicorn", "--bind=0.0.0.0:5000", "--log-level=info", "service:app", "--workers", "3", "--threads", "4", "--access-logfile", "-"]
