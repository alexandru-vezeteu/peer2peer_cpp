FROM cgr.dev/chainguard/wolfi-base AS builder

RUN apk add --no-cache \
    build-base \
    gcc-14 \
    meson \
    ninja \
    pkgconf \
    openssl-dev

WORKDIR /src

COPY meson.build .
COPY src/ src/

RUN CC=gcc-14 CXX=g++-14 meson setup build --buildtype=release && \
    meson compile -C build

FROM cgr.dev/chainguard/wolfi-base AS runtime

RUN apk add --no-cache libstdc++ openssl

WORKDIR /app
COPY --from=builder /src/build/p2p .

ENTRYPOINT ["./p2p"]