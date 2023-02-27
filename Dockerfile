FROM python:3.11-alpine

RUN apk update \
 && apk -X https://dl-cdn.alpinelinux.org/alpine/edge/main --no-cache add git>2.35.2-r0 \
 && mkdir /app \
 && rm -rf /var/lib/apt/lists/*

COPY src/main.py /app/main.py
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt

ENTRYPOINT ["/app/main.py"]
