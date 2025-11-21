FROM python:3.12-rc-bookworm

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

CMD [ "uvicorn", "main:app", "--port=2010", "--host=0.0.0.0" ]