FROM python:3.13-slim

WORKDIR /app
COPY ./app /app

RUN pip install --no-cache-dir fastapi uvicorn sqlalchemy psycopg2-binary passlib[bcrypt] cryptography aiogram

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
