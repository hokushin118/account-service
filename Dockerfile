FROM python:3.9-slim

# Create working folder
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application contents
COPY service/ ./service/

# Switch to a non-root user
RUN useradd --uid 1000 cbotee && chown -R cbotee /app
USER cbotee

# Expose service port
EXPOSE 5000

# Use gunicorn with a process manager (better for production)
CMD ["gunicorn", "--bind=0.0.0.0:5000", "--log-level=info", "service:app", "--workers", "3", "--threads", "4", "--access-logfile", "-"]
