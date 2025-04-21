# Builder stage
FROM python:3.9-slim-bullseye AS builder

# Set the working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN echo "----> Installing build dependencies..." && \
    pip install --no-cache-dir --prefer-binary -r requirements.txt && \
    # Install the specific core library version from TestPyPI
    echo "----> Installing cba-core-lib from TestPyPI..." && \
    pip install --no-cache-dir --index-url https://test.pypi.org/simple/ cba-core-lib==1.0.19

# Local development
#COPY dist/ ./dist
#RUN pip install dist/cba_core_lib-1.0.19-py3-none-any.whl

# Copy the application contents
COPY service/ ./service/

# Create a non-root user for security
# Using a fixed UID (e.g., 1000) is common practice
RUN useradd --uid 1000 --create-home --shell /bin/bash cbotee && \
    chown -R cbotee:cbotee /app

# Final image stage
FROM python:3.9-slim-bullseye

# Set the working directory (should match builder)
WORKDIR /app

# Create a non-root user for security
# Using a fixed UID (e.g., 1000) is common practice
RUN useradd --uid 1000 --create-home --shell /bin/bash cbotee && \
    chown -R cbotee:cbotee /app

# Install dependencies in final stage
COPY requirements.txt .

RUN echo "----> Installing runtime dependencies..." && \
    pip install --no-cache-dir --prefer-binary -r requirements.txt && \
    # Install the specific core library version from TestPyPI
    echo "----> Installing cba-core-lib from TestPyPI..." && \
    pip install --no-cache-dir --index-url https://test.pypi.org/simple/ cba-core-lib==1.0.19

# Local development
#COPY dist/ ./dist
#RUN pip install dist/cba_core_lib-1.0.19-py3-none-any.whl

# Copy the application code from the builder stage.
# This copy preserves the ownership set in the builder stage.
COPY --from=builder --chown=cbotee:cbotee /app/service /app/service

# Set common Python environment variables
# Prevents python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Prevents python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER cbotee

# Expose the port the application will run on
# Ensure this matches the port in the CMD '--bind' argument
EXPOSE 5000

# Use gunicorn with a process manager (better for production)
# main:app : Points to the FastAPI application instance named 'app'
#               within the 'service.main' module.
#               Adjust if your entry point is different (e.g., main:app).
# --workers: Number of worker processes. Tune based on CPU cores and load.
# --access-logfile -: Logs access logs to stdout.
# --error-logfile -: Logs error logs to stderr (Gunicorn default).
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--log-level", "info", \
     "--access-logfile", "-", \
     "--workers", "1", \
     "service:app"]
