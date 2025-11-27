FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "scikit-learn==1.7.2"

COPY . .

# Ensure ML model + scaler are included (redundant but explicit)
COPY threatkit/malware/models /app/threatkit/malware/models
COPY threatkit/malware/rules  /app/threatkit/malware/rules

ENV FLASK_APP=app.py
ENV FLASK_ENV=development

EXPOSE 5000
CMD ["flask", "run", "--host=0.0.0.0"]
