# lego's official image is Alpine, so the entrypoint runs under its busybox sh.
FROM goacme/lego:v4.25.2@sha256:01d6d764dec61ca9d39f43320657c5652106e9d9f326bde6d402c4853451a40b
RUN ln -s /lego /usr/local/bin/lego
COPY --chmod=0755 acme-client.sh /usr/local/bin/acme-client.sh
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/acme-client.sh"]
