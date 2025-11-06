FROM python:3.10-slim

WORKDIR /app

# Copy only auth_session project to reduce context size
COPY ../../ /app/

RUN pip install --no-cache-dir -r projects/auth_session/deployment/requirements.txt

EXPOSE 8000

CMD ["uvicorn", "projects.auth_session.deployment.api:app", "--host", "0.0.0.0", "--port", "8000"]


