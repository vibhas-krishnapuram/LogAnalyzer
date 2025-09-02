FROM python:3.11-slim

## WORKING DIRECTORY
WORKDIR /LogScanner


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY Main .
COPY templates .


EXPOSE 5000

CMD ["python", "app.py"]

