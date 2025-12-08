# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install deps
COPY scripts /opt/resolve/scripts
RUN /opt/resolve/scripts/install-deps.sh && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy in resolve tools
COPY --exclude=build/ klee /opt/resolve/klee
COPY --exclude=target/ libresolve /opt/resolve/libresolve
COPY --exclude=build/ llvm-plugin /opt/resolve/llvm-plugin
COPY --exclude=build/ reach /opt/resolve/reach
COPY --exclude=build/ resolve-facts /opt/resolve/resolve-facts
COPY linker /opt/resolve/linker
COPY mcp /opt/resolve/mcp
COPY reach-wrapper /opt/resolve/reach-wrapper
COPY Makefile /opt/resolve/Makefile

# Executable Scripts
RUN chmod -R 777 /opt/resolve/linker /opt/resolve/reach-wrapper

# Build
WORKDIR /opt/resolve/
RUN PATH="$PATH:~/.cargo/bin" make

FROM builder AS git-version
COPY .git/ /resolve-git/

RUN export RESOLVE_VERSION=$(git -C /resolve-git rev-parse HEAD) \
    && echo "resolve version: $RESOLVE_VERSION" \
    && echo -n $RESOLVE_VERSION > /RESOLVE_VERSION

FROM builder AS resolve
COPY --from=git-version /RESOLVE_VERSION /RESOLVE_VERSION
