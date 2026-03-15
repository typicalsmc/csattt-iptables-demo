FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iptables \
    iptables-persistent \
    conntrack \
    python3 \
    python3-pip \
    iputils-ping \
    net-tools \
    iproute2 \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server.py /app/server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
