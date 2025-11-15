FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y --no-install-recommends \
    curl \
    sudo \
    time \
    ca-certificates
RUN update-ca-certificates

# Copy in resolve tools
COPY llvm-plugin /opt/resolve/llvm-plugin
COPY libresolve /opt/resolve/libresolve
COPY reach /opt/resolve/reach
COPY linker /opt/resolve/linker
COPY reach-wrapper /opt/resolve/reach-wrapper
COPY scripts /opt/resolve/scripts
COPY Makefile /opt/resolve/Makefile

# Build
WORKDIR /opt/resolve/
RUN echo -n "resolve version: "
RUN git log --pretty=format:'%h' -n 1 | tee /RESOLVE_VERSION
RUN ./scripts/install-deps.sh
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
RUN PATH="$PATH:~/.cargo/bin" make

# Executable Scripts
RUN chmod -R 777 /opt/resolve/linker /opt/resolve/reach-wrapper
