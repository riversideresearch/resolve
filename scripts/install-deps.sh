apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    clang-format \
    lld \
    cmake \
    ninja-build \
    python3-lit \
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
    curl

apt-get clean
rm -rf /var/lib/apt/lists/*

# Python packages
python3 -m pip install lit wllvm univers --break-system-packages

# Rust installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y
. ~/.cargo/env
echo 'export PATH="$PATH:~/.cargo/bin"' >> /etc/profile
rustup toolchain install nightly --allow-downgrade --profile minimal --component clippy
echo "Rust installation:"
rustc --version
cargo --version
