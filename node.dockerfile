FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    meson \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY meson.build .
COPY src/ src/

RUN meson setup build --buildtype=release && \
    meson compile -C build

FROM debian:bookworm-slim AS runtime



WORKDIR /app
COPY --from=builder /src/build/p2p .


ENTRYPOINT ["./p2p"]
