FROM cgr.dev/chainguard/wolfi-base AS builder

RUN apk add --no-cache \
    build-base \
    gcc-14 \
    meson \
    ninja \
    pkgconf \
    openssl-dev \
    libsodium-dev

WORKDIR /src

COPY meson.build .
COPY src/ src/

RUN CC=gcc-14 CXX=g++-14 meson setup build --buildtype=release && \
    meson compile -C build p2p

FROM cgr.dev/chainguard/wolfi-base AS runtime

RUN apk add --no-cache \
    libstdc++ \
    openssl \
    libsodium \
    netcat-openbsd

WORKDIR /app
COPY --from=builder /src/build/p2p .
COPY node-entrypoint.sh entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
