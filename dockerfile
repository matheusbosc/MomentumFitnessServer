FROM python:3.12-rc-bookworm

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENV HOST="192.168.2.180"
ENV PORT="2010"

CMD ["uvicorn", "main:app", "--port", PORT, "--host", HOST]