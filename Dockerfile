FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY aegis_sovereign ./aegis_sovereign
COPY tests ./tests
COPY verify_imports.py verify_config.py verify_unified.py Makefile ./

# The package declares zero runtime dependencies; setuptools is provided by
# the pinned Python image and the editable tree is never written outside /app.
RUN python -m pip install --no-cache-dir --no-deps .

EXPOSE 8787
CMD ["aegis-sovereign", "serve-edge", "--host", "0.0.0.0", "--port", "8787"]
