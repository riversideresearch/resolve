# syntax=docker/dockerfile:1
#
# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

FROM ubuntu:24.04 AS base
ARG RESOLVE_PREFIX=/opt/resolve

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install deps
COPY scripts /opt/resolve/scripts
RUN /opt/resolve/scripts/install-deps.sh && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add resolve to PATH
ENV PATH="/opt/resolve/bin:${PATH}"

FROM ubuntu:24.04 AS cmake-builder
ARG RESOLVE_PREFIX=/opt/resolve
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    git \
    libssl-dev \
    pkg-config \
    make \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Build/Install cmake
ARG CMAKE_REPO_URL="https://gitlab.kitware.com/cmake/cmake.git"
ARG CMAKE_BRANCH="v4.3.0"
RUN git clone --depth 1 --branch "${CMAKE_BRANCH}" "${CMAKE_REPO_URL}" /build-cmake \
    && cd /build-cmake \
    && ./bootstrap --parallel="$(nproc)" --prefix=$RESOLVE_PREFIX \
    && make -j"$(nproc)"

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
COPY resolve-cli /resolve/resolve-cli
COPY Makefile /resolve/Makefile
COPY CMakeLists.txt /resolve/CMakeLists.txt

# Build
WORKDIR /resolve/
RUN PATH=$PATH:~/.cargo/bin make build install

FROM base AS git-version
COPY .git/ /resolve-git/

RUN export RESOLVE_VERSION=$(git -C /resolve-git rev-parse HEAD) \
    && echo "resolve version: $RESOLVE_VERSION" \
    && echo -n $RESOLVE_VERSION > /RESOLVE_VERSION

FROM base AS resolve
RUN --mount=from=cmake-builder,source=/build-cmake,target=/build-cmake,rw make -C /build-cmake install 
COPY --from=builder /opt/resolve /opt/resolve
COPY --from=git-version /RESOLVE_VERSION /RESOLVE_VERSION
