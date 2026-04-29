# Asterisk Docker image for rsiprtp integration testing
# Use official Asterisk image from sangoma/asterisk
FROM debian:bullseye-slim

# Install Asterisk from Debian repos (available in bullseye)
RUN apt-get update && apt-get install -y \
    asterisk \
    asterisk-core-sounds-en \
    asterisk-moh-opsound-wav \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY pjsip.conf /etc/asterisk/pjsip.conf
COPY extensions.conf /etc/asterisk/extensions.conf
COPY rtp.conf /etc/asterisk/rtp.conf

# Expose SIP and RTP ports
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 10000-20000/udp

# Run Asterisk in foreground
CMD ["asterisk", "-f", "-vvv"]
