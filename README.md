<div align="center">
    <picture style="width: 100%; height: auto;">
        <source srcset=".github/media/resolve_logo_white.png"  media="(prefers-color-scheme: dark)">
        <img src=".github/media/resolve_logo_black.png">
    </picture>
</div>

![GitHub License](https://img.shields.io/github/license/riversideresearch/resolve?link=https%3A%2F%2Fopensource.org%2Flicense%2Flgpl-3-0)
![GitHub Tag](https://img.shields.io/github/v/tag/riversideresearch/resolve)

---

**RESOLVE** is an LLVM-based software security tool designed to anticipate, triage and remediate CVEs. It combines binary metadata based on enhanced software bills-of-material, or eSBOMs, with runtime components and program analysis tools that together speed up the process of identifying and remediating bugs.

Please see our [documentation website](https://riversideresearch.github.io/resolve) for [installation](https://riversideresearch.github.io/resolve/latest/installation/) and [usage](https://riversideresearch.github.io/resolve/latest/components/resolve-cli/resolve-cli/).


#### Quick Install

```bash
# Dependencies (Ubuntu)
sudo apt update && sudo apt install -y bash coreutils clang llvm binutils zstd

# RESOLVE
curl -fL https://github.com/riversideresearch/resolve/releases/latest/download/resolve-linux-x86_64.tar.gz \
-o /tmp/resolve-linux-x86_64.tar.gz && sudo tar -C / -xzf /tmp/resolve-linux-x86_64.tar.gz
```