FROM python:3.12-slim
WORKDIR /app
COPY app.py .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt || true
EXPOSE 8000
ENV PYTHONUNBUFFERED=1
CMD ["python", "app.py"]
