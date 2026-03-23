FROM cgr.dev/chainguard/wolfi-base

# Install development dependencies
# Note: 'git' is added because VS Code Dev Containers require it for version control features
RUN apk add --no-cache \
    build-base \
    gcc-14 \
    meson \
    ninja \
    pkgconf \
    openssl-dev \
    libsodium-dev \
    git

# Set environment variables so Meson automatically uses gcc-14
ENV CC=gcc-14
ENV CXX=g++-14

# Set a standard workspace directory
WORKDIR /workspace

# Keep the container running indefinitely so the IDE can attach to it
CMD ["tail", "-f", "/dev/null"]