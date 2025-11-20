FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure ML model + scaler are included
COPY threatkit/malware/models /app/threatkit/malware/models
COPY threatkit/malware/rules /app/threatkit/malware/rules

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
