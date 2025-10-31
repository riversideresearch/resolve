#!/usr/bin/env bash 

set -e 

echo "Installing dependencies for resolve..."

# Update and install commands
UPDATE_CMD="sudo apt-get update"
INSTALL_CMD="sudo apt-get install -y --no-install-recommends"

PKGS="build-essential \
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
    pkg-config \
    python3-pip \
    python3-zstd \
    zstd \
    llvm-dev \
    clang-16 \
    llvm-16 \
    libncurses-dev \
    libz3-dev \
    zlib1g-dev"

# Update package list
echo "[*] Updating packages..."
eval "$UPDATE_CMD"

# Install system dependencies
echo "[*] Installing dependencies"
eval "$INSTALL_CMD $PKGS"

# Install python packages
python3 -m pip install lit wllvm univers --break-system-packages

# Install rust
if ! command -v rustc >/dev/null 2&>1; then
    echo "[*] Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y  
    source "$HOME/.cargo/env"
else 
    echo "[*] Rust is already installed."
    rustc --version 
    cargo --version

fi 

echo " All dependencies installed successfully."