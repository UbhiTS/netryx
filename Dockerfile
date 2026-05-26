# NetScanner — self-contained container image.
# Pure-stdlib Python app; the only OS deps are the tools it shells out to
# (ping, ip neigh/route, arp). Build small and run with HOST networking so the
# container can actually see your LAN, ARP table, mDNS and SNMP traffic.

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY netscanner.py ui.html /app/

# Scan history, device names/notes and the downloaded IEEE vendor DB persist here.
ENV NETSCANNER_DATA=/data \
    NETSCANNER_HOST=0.0.0.0 \
    NETSCANNER_PORT=8765 \
    NETSCANNER_NO_BROWSER=1

VOLUME ["/data"]
EXPOSE 8765

# Note: with `--network host` (recommended) the EXPOSE above is informational;
# the app binds directly to the host's port 8765.
CMD ["python", "netscanner.py"]
