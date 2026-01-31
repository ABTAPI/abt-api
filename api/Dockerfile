
FROM python:3.11-slim
WORKDIR /app
COPY abt_api_secure.py .
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" python-jose slowapi requests pydantic
EXPOSE 8000
CMD ["uvicorn", "abt_api_secure:app", "--host", "0.0.0.0", "--port", "8000"]
