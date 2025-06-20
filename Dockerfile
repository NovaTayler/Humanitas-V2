FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY templates/ ./templates/

RUN python3 -c "from cryptography.fernet import Fernet; open('secrets.key', 'wb').write(Fernet.generate_key())"

EXPOSE 5000 8001

CMD ["python3", "main.py"]
