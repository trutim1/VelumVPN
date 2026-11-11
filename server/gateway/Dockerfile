# syntax=docker/dockerfile:1.7
FROM docker.io/library/golang:1.25.13-bookworm@sha256:e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48 AS awg-engine
ARG AWG_GO_COMMIT=0527dfa47639714dd8f5c9ffbd9d40d19083f0ba
ARG BUILD_JOBS=2
RUN apt-get update && apt-get install -y --no-install-recommends git make ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git /src/amneziawg-go \
    && cd /src/amneziawg-go \
    && git checkout --detach "$AWG_GO_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$AWG_GO_COMMIT" \
    && GOMAXPROCS="$BUILD_JOBS" make \
    && git archive --format=tar.gz --output=/amneziawg-go-source.tar.gz HEAD

FROM docker.io/library/debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS awg-tools
ARG AWG_TOOLS_COMMIT=d09ecc38425082e472368dd2bf8c4c42d10cae03
ARG BUILD_JOBS=2
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev pkg-config ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git /src/amneziawg-tools \
    && cd /src/amneziawg-tools \
    && git checkout --detach "$AWG_TOOLS_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$AWG_TOOLS_COMMIT" \
    && make -j"$BUILD_JOBS" -C src \
    && git archive --format=tar.gz --output=/amneziawg-tools-source.tar.gz HEAD

FROM docker.io/library/debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS unbound-builder
ARG UNBOUND_VERSION=1.26.0
ARG UNBOUND_SHA256=77458a7156e275c0b7b17fabcb357cb12445d95cfcb26fb9bb7d5ecba45e0b63
ARG BUILD_JOBS=2
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl libexpat1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --show-error --silent --location \
      "https://www.nlnetlabs.nl/downloads/unbound/unbound-${UNBOUND_VERSION}.tar.gz" \
      --output /unbound.tar.gz \
    && echo "${UNBOUND_SHA256}  /unbound.tar.gz" | sha256sum --check --strict \
    && mkdir -p /src/unbound \
    && tar --extract --gzip --file /unbound.tar.gz --strip-components=1 --directory /src/unbound \
    && cd /src/unbound \
    && ./configure --prefix=/usr --sysconfdir=/etc --with-conf-file=/etc/unbound/unbound.conf --with-pidfile=/run/unbound.pid --disable-shared --disable-rpath \
    && make -j"$BUILD_JOBS" \
    && ./unbound -V | grep -F "Version ${UNBOUND_VERSION}"

FROM docker.io/library/debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
LABEL org.opencontainers.image.title="Velum Gateway" \
      org.opencontainers.image.description="Pinned AmneziaWG 3.0.2 userspace gateway for Velum" \
      org.opencontainers.image.version="0.1.0-preview" \
      org.opencontainers.image.licenses="GPL-3.0-only AND MIT AND GPL-2.0-only"
RUN apt-get update && apt-get install -y --no-install-recommends busybox ca-certificates dns-root-data dumb-init iproute2 iptables libexpat1 libssl3t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=awg-engine /src/amneziawg-go/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=awg-tools /src/amneziawg-tools/src/wg /usr/local/bin/awg
COPY --from=awg-tools /src/amneziawg-tools/src/wg-quick/linux.bash /usr/local/bin/awg-quick
COPY --from=unbound-builder /src/unbound/unbound /usr/sbin/unbound
COPY --from=unbound-builder /src/unbound/unbound-checkconf /usr/sbin/unbound-checkconf
COPY --from=awg-engine /src/amneziawg-go/LICENSE /usr/share/licenses/velum/amneziawg-go-MIT.txt
COPY --from=awg-tools /src/amneziawg-tools/COPYING /usr/share/licenses/velum/amneziawg-tools-GPL-2.0.txt
COPY --from=unbound-builder /src/unbound/LICENSE /usr/share/licenses/velum/Unbound-BSD-3-Clause.txt
COPY LICENSE /usr/share/licenses/velum/Velum-GPL-3.0.txt
COPY --from=awg-engine /amneziawg-go-source.tar.gz /usr/share/velum/source/amneziawg-go-v3.0.2.tar.gz
COPY --from=awg-tools /amneziawg-tools-source.tar.gz /usr/share/velum/source/amneziawg-tools-v3.0.20260730.tar.gz
COPY --from=unbound-builder /unbound.tar.gz /usr/share/velum/source/unbound-1.26.0.tar.gz
COPY gateway/entrypoint.sh /usr/local/libexec/velum-entrypoint
COPY gateway/unbound.example.conf /etc/unbound/unbound.conf
RUN chmod 0755 /usr/local/bin/amneziawg-go /usr/local/bin/awg /usr/local/bin/awg-quick /usr/local/libexec/velum-entrypoint /usr/sbin/unbound /usr/sbin/unbound-checkconf \
    && mkdir -p /config /run/amneziawg /run/unbound \
    && printf '%s\n' 'AWG Go: https://github.com/amnezia-vpn/amneziawg-go @ 0527dfa47639714dd8f5c9ffbd9d40d19083f0ba / v3.0.2 (MIT)' 'AWG tools: https://github.com/amnezia-vpn/amneziawg-tools @ d09ecc38425082e472368dd2bf8c4c42d10cae03 / v3.0.20260730 (GPL-2.0)' 'Unbound: https://www.nlnetlabs.nl/downloads/unbound/unbound-1.26.0.tar.gz @ sha256:77458a7156e275c0b7b17fabcb357cb12445d95cfcb26fb9bb7d5ecba45e0b63 (BSD-3-Clause)' 'License texts: /usr/share/licenses/velum' 'Corresponding pinned source archives: /usr/share/velum/source' > /THIRD_PARTY_NOTICES
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/libexec/velum-entrypoint"]
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD test "$(/usr/local/bin/awg show velum0 listen-port 2>/dev/null)" = 42016
