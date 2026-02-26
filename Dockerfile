# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install deps
COPY scripts /opt/resolve/scripts
RUN /opt/resolve/scripts/install-deps.sh && apt-get clean && rm -rf /var/lib/apt/lists/*

FROM base AS builder
# Copy in resolve tools
COPY cmake /resolve/cmake
COPY klee /resolve/klee
COPY klee-uclibc-160 /resolve/klee-uclibc-160
COPY resolve-cc /resolve/resolve-cc
COPY resolve-cveassert /resolve/resolve-cveassert
COPY reach /resolve/reach
COPY resolve-facts /resolve/resolve-facts
COPY mcp /resolve/mcp
COPY resolve-triage /resolve/resolve-triage
COPY Makefile /resolve/Makefile
COPY CMakeLists.txt /resolve/CMakeLists.txt

# Executable Scripts
RUN chmod -R 777 /resolve/resolve-cc/linker /resolve/resolve-cveassert/resolvecc

# Add resolvecc to PATH
ENV PATH="/resolve/resolve-cveassert:${PATH}"

# Build
WORKDIR /resolve/
RUN PATH=$PATH:~/.cargo/bin make build install

FROM base AS git-version
COPY .git/ /resolve-git/

RUN export RESOLVE_VERSION=$(git -C /resolve-git rev-parse HEAD) \
    && echo "resolve version: $RESOLVE_VERSION" \
    && echo -n $RESOLVE_VERSION > /RESOLVE_VERSION

FROM base AS resolve
COPY --from=builder /opt/resolve /opt/resolve
COPY --from=git-version /RESOLVE_VERSION /RESOLVE_VERSION