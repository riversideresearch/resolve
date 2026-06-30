## Install Dependencies

To use pre-built **RESOLVE**, you need the following:

- bash
- coreutils
- clang-18
- llvm-18
- binutils
- zstd

On **Ubuntu**, try:

```bash
sudo apt update
sudo apt install -y bash coreutils clang llvm binutils zstd
```

!!! tip
    If you get errors with clang not being found, you might need to create a symlink to the proper name:

    ```bash
    sudo ln -sf /usr/bin/clang-18 /usr/local/bin/clang
    sudo ln -sf /usr/bin/clang++-18 /usr/local/bin/clang++
    ```

## One-Liner RESOLVE Install

You can install the latest GitHub release of **RESOLVE** using the following command:

```bash
curl -fL https://github.com/riversideresearch/resolve/releases/latest/download/resolve-linux-x86_64.tar.gz \
    -o /tmp/resolve-linux-x86_64.tar.gz && sudo tar -C / -xzf /tmp/resolve-linux-x86_64.tar.gz
```

!!! note
    This one-liner syntax assumes you have `curl` and `ca-certificates` already installed. 

## Building from source

See [building RESOLVE from source](development/building-from-source.md) for information on building **RESOLVE** binaries.
