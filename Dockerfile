FROM python:3-alpine
LABEL maintainer="https://github.com/sylvandb/tplink-smartplug"

WORKDIR /app

COPY . .

# udp reply port
EXPOSE 61000/udp

ENTRYPOINT [ "python3", "tplink_smartplug.py" ]
