FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install deps
COPY scripts /opt/resolve/scripts
RUN /opt/resolve/scripts/install-deps.sh && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy in resolve tools
COPY llvm-plugin /opt/resolve/llvm-plugin
COPY libresolve /opt/resolve/libresolve
COPY reach /opt/resolve/reach
COPY linker /opt/resolve/linker
COPY reach-wrapper /opt/resolve/reach-wrapper
COPY Makefile /opt/resolve/Makefile

# Executable Scripts
RUN chmod -R 777 /opt/resolve/linker /opt/resolve/reach-wrapper

# Build
WORKDIR /opt/resolve/
RUN PATH="$PATH:~/.cargo/bin" make

# Mark Version
RUN echo -n "resolve version: "
RUN git log --pretty=format:'%h' -n 1 | tee /RESOLVE_VERSION
