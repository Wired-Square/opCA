# The opca-acme ApplianceOS app, from the vendored context stage-broker-src.sh
# makes, with the page build-acme-app.sh built in ui/dist; build-acme-app.sh
# adds the manifest label. One platform per build.
# glibc and libssl3 as the .deb links them, run on the build's Debian release.
# No HEALTHCHECK: the console probes healthz over app.sock.
FROM rust:1.99-bookworm@sha256:cfcbed05398d0f6f81b7c3a24579475c567f97007ae7837ab421f9ca3e66333d AS build
ARG TARGETARCH
# The staged config links arm64 with lld, for its erratum 843419 fix.
RUN [ "$TARGETARCH" != arm64 ] || { apt-get update && \
    apt-get install -y --no-install-recommends lld && rm -rf /var/lib/apt/lists/*; }
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=opca-acme-target-$TARGETARCH,target=/target \
    cargo build --offline --release --target-dir /target -p opca-acme-broker --bin opca-acme-broker \
    && cp /target/release/opca-acme-broker /usr/local/bin/ \
    && mkdir -p /empty/volume/data /empty/socket/appliance

FROM scratch AS binary
COPY --from=build /usr/local/bin/opca-acme-broker /

FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
COPY --from=build /usr/local/bin/opca-acme-broker /usr/bin/opca-acme-broker
# Built on the host, so no node here, with a .gz beside each file gzip shrinks.
COPY crates/opca-acme-broker/ui/dist /usr/share/opca-acme/ui
# Each copied into its parent, so the parent keeps root's ownership.
COPY --from=build --chown=10001:0 --chmod=0770 /empty/volume/ /
COPY --from=build --chown=10001:0 --chmod=0770 /empty/socket/ /run/
VOLUME ["/data"]
USER 10001:0
ENTRYPOINT ["/usr/bin/opca-acme-broker", "--app"]
