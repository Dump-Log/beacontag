FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections

RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# beacontag.py imports pcapng_writer.py -- keep them together in the build
# context (same directory as this Dockerfile) so this COPY picks both up.
COPY beacontag.py pcapng_writer.py ./

# Run as non-root. Reading pcaps and writing pcapng needs no elevated
# capabilities, so a plain unprivileged user is enough.
#
# PUID/PGID default to 1000 (the first user on most single-user Linux desktops,
# incl. Kali). Build with your own to guarantee output files on the mounted
# /data are owned by you, so a plain `docker run` needs no --user flag:
#   docker build --build-arg PUID=$(id -u) --build-arg PGID=$(id -g) -t beacontag .
#
# Reuse a group/user if the requested GID/UID already exists in the base image
# (e.g. macOS gid 20 collides with Debian's 'dialout'), so the build can't fail
# on a collision.
ARG PUID=1000
ARG PGID=1000
RUN if ! getent group ${PGID} >/dev/null; then groupadd -g ${PGID} pcapuser; fi \
    && if ! getent passwd ${PUID} >/dev/null; then \
           useradd -r -u ${PUID} -g ${PGID} -m pcapuser; \
       fi \
    && mkdir -p /data \
    && chown -R ${PUID}:${PGID} /app /data
USER ${PUID}:${PGID}

# Mount your pcaps at /data, e.g.:
#   docker run --rm -v "$PWD/data:/data" beacontag /data/capture.pcap
WORKDIR /data
ENTRYPOINT ["python3", "/app/beacontag.py"]
CMD ["--help"]
