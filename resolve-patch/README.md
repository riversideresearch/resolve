# resolve-patch

`resolve-patch` allows patching in-the-wild binaries in-place via decompilation and recompilation with llvm patch files.

Setting the `"output"` key value in your `vulernabilities.json` to `"patch"` will produce a `resolve-patch.ll` file next to an un-instrumented binary.

Using `llvm-mctoll`, you can produce a dissassembled `{binary}-dis.ll` file like so:

```bash
llvm-mctoll -I "{YOUR_PATH_GOES_HERE}/mctoll-prototypes.h" {binary}
```

To reconcile the dissassembled program with the patch, and produce a new `.ll` file for recompilation, you can run the resolve patcher:

```bash
patcher.py -i {binary}-dis.ll -p resolve-patch.ll -o {binary}-patched.ll
```

With the patched `.ll`, simply recompile with `clang` like so:

```bash
clang {binary}-patched.ll -o {binary}-patched
```

## setup

see `./llvm-mctoll/README.md` for instructions on performing a in-tree build.

## limitations

llvm-mctoll cannot lift the following:
- sse/avx/neon (use `clange -mno-sse`)
- Windows/OSX binaries
- some C++ patterns (unclear)

See [llvm-mctoll current status](https://github.com/microsoft/llvm-mctoll/tree/master#current-status) for more information.
