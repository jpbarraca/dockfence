# dockfence — host-level firewall container
FROM python:3.12-slim

# nft binary + kernel userspace bits; CA certs for https egress from the app
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables ca-certificates kmod conntrack \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dockfence/ ./dockfence/

ENV FW_DB=/var/lib/dockfence/dockfence.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN mkdir -p /var/lib/dockfence
VOLUME /var/lib/dockfence
EXPOSE 8420

# runs on the HOST network namespace (network_mode: host) so it programs the
# host's nftables + receives nflog netlink traffic
ENTRYPOINT ["python3", "-m", "dockfence"]
