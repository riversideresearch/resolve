# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

FROM resolve:latest

WORKDIR /challenge

# Copy source code with workspace override support
ARG WORKSPACE=""
COPY src /challenge/src
COPY workspaces /tmp/workspaces/
RUN if [ -n "$WORKSPACE" ] && [ -d "/tmp/workspaces/${WORKSPACE}/src" ]; then \
        echo "Overriding src with workspace: $WORKSPACE"; \
        rm -rf /challenge/src && \
        cp -r /tmp/workspaces/${WORKSPACE}/src /challenge/src; \
    else \
        echo "Using default src"; \
    fi && \
    rm -rf /tmp/workspaces

COPY vulnerabilities.json /challenge/vulnerabilities.json

# Set resolve environment variables
ARG RESOLVE_LABEL_CVE
ENV RESOLVE_LABEL_CVE=${RESOLVE_LABEL_CVE}

# Configure and build using CMake with resolve toolchain
# When RESOLVE_LABEL_CVE is set, use clang with CVEAssert plugin and link libresolve
RUN mkdir -p /challenge/build && \
    if [ -n "$RESOLVE_LABEL_CVE" ]; then \
        echo "Building with resolve instrumentation"; \
        clang -fpass-plugin=/opt/resolve/llvm-plugin/build/libCVEAssert.so \
          -L/opt/resolve/libresolve/target/release -lresolve \
          -Wl,-rpath=/opt/resolve/libresolve/target/release \
          /challenge/src/main.c -o /challenge/build/example_app; \
    else \
        echo "Building without instrumentation"; \
        cmake -S /challenge/src -B /challenge/build -DCMAKE_BUILD_TYPE=Debug && \
        cmake --build /challenge/build --target example_app; \
    fi

RUN useradd -m user && chown -R user:user /challenge

USER user

CMD ["/challenge/build/example_app"]
