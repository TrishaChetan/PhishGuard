FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Train at build time so the image is self-contained (swap in --data for a real dataset)
RUN python -m phishguard.train
EXPOSE 8000
RUN useradd -m app && chown -R app /app
USER app
CMD ["uvicorn", "phishguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
