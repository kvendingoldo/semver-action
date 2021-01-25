FROM python:3.8-alpine

RUN apk --no-cache add git \
 && mkdir /app \
 && rm -rf /var/lib/apt/lists/*

COPY main.py /app/main.py
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

ENTRYPOINT ["/app/main.py"]
