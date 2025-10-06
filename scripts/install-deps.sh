apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    clang-format \
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
    vim \
    python3-pip \
    python3-zstd \
    zstd \
    llvm-dev \
    gdb \
    lldb \
    clang-16 \
    llvm-16 \
    libncurses-dev \
    libz3-dev \
    zlib1g-dev \
    curl \
    rustc \
    cargo

apt-get clean
rm -rf /var/lib/apt/lists/*

curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y
rustup toolchain install nightly
rustup default nightly

python3 -m pip install lit wllvm --break-system-packages

