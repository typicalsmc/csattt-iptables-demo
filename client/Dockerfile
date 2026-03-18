FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iptables \
    ipset \
    openssh-client \
    iputils-ping \
    net-tools \
    iproute2 \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy requests paramiko

COPY demo.py /demo.py

# Default: run the full automated demo.
# Override with: docker exec -it iptables_client bash
CMD ["python3", "-u", "/demo.py"]
