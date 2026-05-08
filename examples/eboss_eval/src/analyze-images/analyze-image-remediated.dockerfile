##### The PLAN(tm) #####
# Build the resolve builder if it doesn't exist: 
# $ docker build --target builder -t resolve-builder:latest .
#
# And then make sure that the resolve image exists:
# $ foobar

FROM resolve-builder:latest AS build

# Disable interactive prompts during package installs
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    lld \
    cmake \
    ninja-build \
    git \
    make \
    wget \
    curl \
    zip \
    unzip \
    time \
    ca-certificates \
    pkg-config \
    autoconf autoconf-archive automake libtool \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install vcpkg
# ENV VCPKG_ROOT=/opt/vcpkg
# ENV PATH="${VCPKG_ROOT}:${PATH}"

# RUN git clone --depth 1 --branch 2025.03.19 https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} && \
#     ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# Set up environment variables for build
# ENV TOOLCHAIN_FILE=/opt/toolchain/challenge-toolchain.cmake
# ENV TRIPLET=x64-linux-challenge
ENV VCPKG_OVERLAY_PORTS=/opt/vcpkg-overlays/ports
# ENV VCPKG_OVERLAY_TRIPLETS=/opt/vcpkg-overlays/triplets

# Create expected directories and copy toolchain files
# RUN mkdir -p /opt/toolchain /opt/vcpkg-overlays/ports /opt/vcpkg-overlays/triplets

# COPY toolchains/challenge-toolchain.cmake /opt/toolchain/challenge-toolchain.cmake
# COPY vcpkg-triplets/x64-linux-challenge.cmake /opt/vcpkg-overlays/triplets/x64-linux-challenge.cmake

# Debug output to verify environment
RUN echo $TOOLCHAIN_FILE && echo $TRIPLET && echo $VCPKG_OVERLAY_PORTS && echo $VCPKG_OVERLAY_TRIPLETS

# Copy application source and overlay ports
WORKDIR /challenge

COPY app /challenge/app
COPY vcpkg-overlays/ports /opt/vcpkg-overlays/ports
COPY vulnerabilities.json /challenge/vulnerabilities.json
ENV RESOLVE_LABEL_CVE="/challenge/vulnerabilities.json"
RUN echo RESOLVE_LABEL_CVE=$RESOLVE_LABEL_CVE

# Configure and build using the values from base stage
RUN /usr/bin/time --format="CHALLENGE_METRICS - Elapsed: %E sec | User: %U sec | System: %S sec | CPU %P" \
    cmake -S /challenge/app -B /challenge/build \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=${TOOLCHAIN_FILE} \
    -DVCPKG_TARGET_TRIPLET=${TRIPLET} \
    -DCMAKE_BUILD_TYPE=Release && \
    /usr/bin/time --format="CHALLENGE_METRICS - Elapsed: %E sec | User: %U sec | System: %S sec | CPU %P" \
    cmake --build /challenge/build --target server --verbose

# Stage 2: Runtime Stage (previously run-base)(previously ubuntu:24.04)
FROM resolve:latest AS runtime

# Disable interactive prompts during package installs
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    socat \
    tar \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV CHALLENGE_BINARY="/challenge/build/server"

RUN useradd -m user

COPY --from=build /challenge/build  /challenge/build
COPY --from=build /challenge/vulnerabilities.json /challenge/vulnerabilities.json
COPY --from=build /opt/vcpkg/buildtrees  /challenge/buildtrees

RUN chown -R user:user /challenge

WORKDIR /challenge

USER user

CMD [ "/challenge/build/server", "5000"]
