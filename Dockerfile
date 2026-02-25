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
COPY cmake /opt/resolve/cmake
COPY klee /opt/resolve/klee
COPY klee-uclibc-160 /opt/resolve/klee-uclibc-160
COPY resolve-cc /opt/resolve/resolve-cc
COPY resolve-cveassert /opt/resolve/resolve-cveassert
COPY reach /opt/resolve/reach
COPY resolve-facts /opt/resolve/resolve-facts
COPY mcp /opt/resolve/mcp
COPY resolve-triage /opt/resolve/resolve-triage
COPY Makefile /opt/resolve/Makefile
COPY CMakeLists.txt /opt/resolve/CMakeLists.txt

# Executable Scripts
RUN chmod -R 777 /opt/resolve/resolve-cc/linker

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
