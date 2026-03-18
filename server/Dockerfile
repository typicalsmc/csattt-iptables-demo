FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iptables \
    iptables-persistent \
    conntrack \
    ipset \
    fail2ban \
    openssh-server \
    rsyslog \
    python3 \
    python3-pip \
    iputils-ping \
    net-tools \
    iproute2 \
    tcpdump \
    curl \
    wget \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server.py /app/server.py
COPY entrypoint.sh /entrypoint.sh
COPY sshd_config /etc/ssh/sshd_config.d/demo.conf
COPY fail2ban-jail.local /etc/fail2ban/jail.local
COPY ipset-ssh.conf /etc/fail2ban/action.d/ipset-ssh.conf
COPY fetch-proxies.sh /fetch-proxies.sh
COPY test-ipset-fail2ban.sh /test-ipset-fail2ban.sh
RUN chmod +x /entrypoint.sh /fetch-proxies.sh /test-ipset-fail2ban.sh

EXPOSE 80 22

ENTRYPOINT ["/entrypoint.sh"]
